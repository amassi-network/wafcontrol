import subprocess
from datetime import timedelta
from io import StringIO
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import call, patch

from django.contrib.auth import get_user_model
from django.test import Client, SimpleTestCase, TestCase
from django.urls import reverse
from django.utils import timezone

from wafinstaller.helper.adapters import detect_crs_version
from wafinstaller.helper.helpers import (
    compare_crs_versions,
    get_crs_version_status,
    get_latest_crs_version,
    is_crs_update_available,
    normalize_version,
    select_latest_crs_version,
)
from wafinstaller.models import AuditEntry, CrsVersion
from wafinstaller.security import (
    DeploymentError,
    ManagedFileError,
    deploy_managed_text,
    resolve_managed_file,
)


class CrsVersionHelperTests(SimpleTestCase):
    def test_normalizes_version_prefix(self):
        self.assertEqual(normalize_version("v4.28.0"), "4.28.0")
        self.assertEqual(normalize_version("V4.28.0"), "4.28.0")

    def test_rejects_invalid_version(self):
        self.assertIsNone(normalize_version("not-a-version"))

    def test_selects_highest_stable_semantic_version(self):
        latest = select_latest_crs_version(
            ["v4.25.1", "v4.28.0", "v4.29.0-rc1", "invalid"]
        )
        self.assertEqual(latest, "4.28.0")

    def test_compares_versions_semantically(self):
        self.assertEqual(compare_crs_versions("4.28.0", "4.25.1"), 1)
        self.assertEqual(compare_crs_versions("v4.25.1", "4.28.0"), -1)
        self.assertEqual(compare_crs_versions("4.28.0", "v4.28.0"), 0)

    def test_only_reports_strictly_newer_release_as_update(self):
        self.assertFalse(is_crs_update_available("4.28.0", "4.25.1"))
        self.assertFalse(is_crs_update_available("4.28.0", "v4.28.0"))
        self.assertTrue(is_crs_update_available("4.28.0", "4.29.0"))

    def test_reports_catalog_behind(self):
        self.assertEqual(
            get_crs_version_status("4.28.0", "4.25.1"), "catalog_behind"
        )

    def test_switch_script_rejects_non_semantic_version_before_system_changes(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "switch_crs_version.sh"

        result = subprocess.run(
            ["/bin/bash", str(script), "../../etc/passwd"],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("Invalid CRS version", result.stdout)

    def test_detects_crs_from_active_apache_include(self):
        def open_active_apache_config(path, *args, **kwargs):
            if path == "/etc/apache2/mods-enabled/security2.conf":
                return StringIO(
                    "Include /etc/modsecurity/crs/coreruleset-4.29.0/rules/*.conf"
                )
            raise FileNotFoundError(path)

        with patch(
            "wafinstaller.helper.adapters._run_basic_script",
            return_value={"server": "apache", "waf": {"version": ""}},
        ), patch("builtins.open", side_effect=open_active_apache_config):
            self.assertEqual(detect_crs_version(), "4.29.0")


class CrsVersionCatalogTests(TestCase):
    def test_latest_version_uses_semver_not_publish_date(self):
        now = timezone.now()
        CrsVersion.objects.create(
            tag="v4.28.0",
            published_at=now - timedelta(days=10),
            zip_url="https://example.test/v4.28.0.zip",
        )
        CrsVersion.objects.create(
            tag="v4.25.1",
            published_at=now,
            zip_url="https://example.test/v4.25.1.zip",
        )

        self.assertEqual(get_latest_crs_version(), "4.28.0")


class CrsEndpointSecurityTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="admin",
            password="test-password",
            is_staff=True,
            is_superuser=True,
        )

    def test_force_fetch_requires_authentication(self):
        response = self.client.post(reverse("wafinstaller:force_fetch_crs_versions"))

        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)

    def test_all_mutation_endpoints_reject_missing_csrf_token(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        endpoints = (
            ("wafinstaller:dashboard", (), {}),
            ("wafinstaller:update_crs_sync", (), {}),
            ("wafinstaller:save_crs_rule", ("rules.conf",), {}),
            ("wafinstaller:toggle_crs_rule", (), {}),
            ("wafinstaller:update_crs_rule", ("rules.conf",), {}),
            ("wafinstaller:switch_crs_version", (), {"version": "v4.28.0"}),
            ("wafinstaller:crs_settings", (), {}),
            ("wafinstaller:force_fetch_crs_versions", (), {}),
            ("wafinstaller:add_custom_rule", (), {}),
            ("wafinstaller:edit_custom_rule", ("100001",), {}),
            ("wafinstaller:delete_custom_rule", (100001,), {}),
            ("wafinstaller:app_settings", (), {}),
            ("wafinstaller:admin_profile", (), {}),
            ("wafinstaller:install_waf_page", (), {}),
        )
        for route_name, args, data in endpoints:
            with self.subTest(route_name=route_name):
                response = client.post(reverse(route_name, args=args), data)
                self.assertEqual(response.status_code, 403)

    @patch("wafinstaller.views.fetch_crs_versions_task")
    @patch("wafinstaller.views.get_installed_crs_version", return_value="4.28.0")
    def test_force_fetch_accepts_authenticated_csrf_protected_request(
        self, _installed_version, fetch_task
    ):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        page = client.get(reverse("wafinstaller:crs_version"))
        csrf_token = page.cookies["csrftoken"].value

        response = client.post(
            reverse("wafinstaller:force_fetch_crs_versions"),
            HTTP_X_CSRFTOKEN=csrf_token,
        )

        self.assertEqual(response.status_code, 302)
        fetch_task.assert_called_once_with()
        audit = AuditEntry.objects.get(action="crs.catalog.refresh")
        self.assertEqual(audit.actor, self.user)
        self.assertEqual(audit.outcome, AuditEntry.Outcome.SUCCEEDED)

class ManagedFileSecurityTests(SimpleTestCase):
    def test_resolves_direct_managed_file(self):
        with TemporaryDirectory() as directory:
            expected = Path(directory, "rules.conf")
            expected.write_text("SecRuleEngine DetectionOnly\n")

            resolved = resolve_managed_file(directory, "rules.conf")

            self.assertEqual(resolved, expected.resolve())

    def test_rejects_traversal_absolute_paths_and_unsupported_types(self):
        with TemporaryDirectory() as directory:
            Path(directory, "rules.conf").write_text("test")
            for filename in ("../rules.conf", "/etc/passwd", "rules.txt"):
                with self.subTest(filename=filename):
                    with self.assertRaises(ManagedFileError):
                        resolve_managed_file(directory, filename)

    def test_rejects_symlink_escaping_managed_directory(self):
        with TemporaryDirectory() as directory, TemporaryDirectory() as outside:
            external = Path(outside, "external.conf")
            external.write_text("secret")
            Path(directory, "linked.conf").symlink_to(external)

            with self.assertRaises(ManagedFileError):
                resolve_managed_file(directory, "linked.conf")

    @patch("wafinstaller.security.subprocess.run")
    def test_no_change_does_not_validate_or_reload(self, run):
        with TemporaryDirectory() as directory:
            target = Path(directory, "rules.conf")
            target.write_text("same\n")

            changed = deploy_managed_text(
                target,
                "same\n",
                test_cmd=["nginx", "-t"],
                reload_cmd=["nginx", "-s", "reload"],
            )

            self.assertFalse(changed)
            run.assert_not_called()

    @patch("wafinstaller.security.subprocess.run")
    def test_successful_change_validates_then_reloads(self, run):
        with TemporaryDirectory() as directory:
            target = Path(directory, "rules.conf")
            target.write_text("old\n")

            changed = deploy_managed_text(
                target,
                "new\n",
                test_cmd=["nginx", "-t"],
                reload_cmd=["nginx", "-s", "reload"],
            )

            self.assertTrue(changed)
            self.assertEqual(target.read_text(), "new\n")
            self.assertEqual(
                run.call_args_list,
                [
                    call(
                        ["nginx", "-t"],
                        check=True,
                        capture_output=True,
                        text=True,
                    ),
                    call(
                        ["nginx", "-s", "reload"],
                        check=True,
                        capture_output=True,
                        text=True,
                    ),
                ],
            )

    @patch("wafinstaller.security.subprocess.run")
    def test_validation_failure_restores_previous_file(self, run):
        from subprocess import CalledProcessError

        run.side_effect = CalledProcessError(1, ["nginx", "-t"])
        with TemporaryDirectory() as directory:
            target = Path(directory, "rules.conf")
            target.write_text("old\n")

            with self.assertRaises(DeploymentError):
                deploy_managed_text(
                    target,
                    "invalid\n",
                    test_cmd=["nginx", "-t"],
                    reload_cmd=["nginx", "-s", "reload"],
                )

            self.assertEqual(target.read_text(), "old\n")

    @patch("wafinstaller.security.subprocess.run")
    def test_reload_failure_restores_previous_file(self, run):
        from subprocess import CalledProcessError

        run.side_effect = [
            None,
            CalledProcessError(1, ["nginx", "-s", "reload"]),
            None,
        ]
        with TemporaryDirectory() as directory:
            target = Path(directory, "rules.conf")
            target.write_text("old\n")

            with self.assertRaises(DeploymentError):
                deploy_managed_text(
                    target,
                    "valid-but-reload-fails\n",
                    test_cmd=["nginx", "-t"],
                    reload_cmd=["nginx", "-s", "reload"],
                )

            self.assertEqual(target.read_text(), "old\n")
            self.assertEqual(run.call_count, 3)


class MutationAuditTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="auditor",
            password="test-password",
            is_staff=True,
            is_superuser=True,
        )
        self.client.force_login(self.user)

    @patch("wafinstaller.views.run_switch_version_script")
    def test_unknown_crs_version_is_rejected_and_audited(self, switch_script):
        response = self.client.post(
            reverse("wafinstaller:switch_crs_version"),
            {"version": "../../etc/passwd"},
        )

        self.assertEqual(response.status_code, 302)
        switch_script.assert_not_called()
        audit = AuditEntry.objects.get(action="crs.version.switch")
        self.assertEqual(audit.outcome, AuditEntry.Outcome.FAILED)
        self.assertNotIn("passwd", audit.details)

    @patch("wafinstaller.views.run_updatecrs_script", return_value=(1, ["failed"]))
    def test_failed_crs_update_returns_conflict_and_is_audited(self, _update):
        response = self.client.post(reverse("wafinstaller:update_crs_sync"))

        self.assertEqual(response.status_code, 409)
        audit = AuditEntry.objects.get(action="crs.update")
        self.assertEqual(audit.outcome, AuditEntry.Outcome.FAILED)
