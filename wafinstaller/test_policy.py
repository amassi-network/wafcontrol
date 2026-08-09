import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import call, patch

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import Client, SimpleTestCase, TestCase
from django.urls import reverse
from django.utils import timezone

from wafinstaller.models import (
    AddressEntry,
    AddressList,
    Attack,
    AuditEntry,
    RuleExclusion,
)
from wafinstaller.policy import (
    AFTER_FILENAME,
    BEFORE_FILENAME,
    PolicyBundle,
    PolicyDeploymentError,
    deploy_policy_bundle,
    render_policy,
)


class ManagedPolicyModelTests(TestCase):
    def test_address_entry_normalizes_network_and_rejects_invalid_input(self):
        address_list = AddressList.objects.create(
            name="office",
            purpose=AddressList.Purpose.TRUSTED,
            description="Administrative office",
        )
        entry = AddressEntry(
            address_list=address_list,
            network="192.0.2.7/24",
            comment="Known office range",
        )
        entry.full_clean()
        self.assertEqual(entry.network, "192.0.2.0/24")

        entry.network = "not-an-address"
        with self.assertRaises(ValidationError):
            entry.full_clean()

    def test_target_exclusion_requires_a_safe_target(self):
        exclusion = RuleExclusion(
            name="contact-description",
            kind=RuleExclusion.Kind.REMOVE_TARGET,
            rule_id=942100,
            rationale="Confirmed false positive",
            owner="operations",
            status=RuleExclusion.Status.APPROVED,
        )
        with self.assertRaises(ValidationError):
            exclusion.full_clean()

        exclusion.target = 'ARGS:description"\nSecRuleEngine Off'
        with self.assertRaises(ValidationError):
            exclusion.full_clean()

    def test_exclusion_metadata_cannot_inject_directives(self):
        exclusion = RuleExclusion(
            name="unsafe\nSecRuleEngine Off",
            kind=RuleExclusion.Kind.REMOVE_RULE,
            rule_id=942100,
            rationale="test",
            owner="operations",
            status=RuleExclusion.Status.APPROVED,
        )
        with self.assertRaises(ValidationError):
            exclusion.full_clean()


class ManagedPolicyRenderingTests(TestCase):
    def _entry(self, address_list, network, **kwargs):
        entry = AddressEntry(
            address_list=address_list,
            network=network,
            comment="Test entry",
            **kwargs,
        )
        entry.full_clean()
        entry.save()
        return entry

    def test_renders_block_observe_and_bypass_with_explicit_semantics(self):
        blocked = AddressList.objects.create(
            name="blocked-scanners",
            purpose=AddressList.Purpose.BLOCK,
            description="Confirmed scanners",
        )
        bypass = AddressList.objects.create(
            name="maintenance-probes",
            purpose=AddressList.Purpose.WAF_BYPASS,
            description="Explicit maintenance bypass",
        )
        trusted = AddressList.objects.create(
            name="trusted-admins",
            purpose=AddressList.Purpose.TRUSTED,
            description="Never auto-ban, still inspect",
        )
        self._entry(blocked, "198.51.100.10")
        self._entry(bypass, "2001:db8::/64")
        self._entry(trusted, "192.0.2.0/24")

        bundle = render_policy()

        self.assertIn("@ipMatch 198.51.100.10/32", bundle.before)
        self.assertIn("deny,status:403", bundle.before)
        self.assertIn("ctl:ruleEngine=Off", bundle.before)
        self.assertNotIn("@ipMatch 192.0.2.0/24", bundle.before)
        self.assertIn("retain WAF inspection", bundle.before)
        self.assertEqual(len(bundle.warnings), 1)
        self.assertEqual(bundle.active_address_entries, 3)

    def test_renders_minimal_scoped_target_exclusion_before_crs(self):
        exclusion = RuleExclusion.objects.create(
            name="ironitia-contact-description",
            kind=RuleExclusion.Kind.REMOVE_TARGET,
            rule_id=942100,
            target="ARGS:description",
            host="ironitia.com",
            path="/api/contact",
            path_match=RuleExclusion.PathMatch.EXACT,
            method="POST",
            rationale="Confirmed false positive",
            owner="operations",
            status=RuleExclusion.Status.APPROVED,
        )

        bundle = render_policy()

        self.assertIn("REQUEST_HEADERS:Host", bundle.before)
        self.assertIn("@streq ironitia.com", bundle.before)
        self.assertIn('REQUEST_URI "@streq /api/contact" "chain"', bundle.before)
        self.assertIn("REQUEST_METHOD", bundle.before)
        self.assertIn("ctl:ruleRemoveTargetById=942100;ARGS:description", bundle.before)
        self.assertNotIn(str(exclusion.rule_id), bundle.after)

    def test_renders_global_static_exclusion_after_crs_and_ignores_expired(self):
        RuleExclusion.objects.create(
            name="global-rule",
            kind=RuleExclusion.Kind.REMOVE_RULE,
            rule_id=920350,
            rationale="Temporary compatibility",
            owner="operations",
            status=RuleExclusion.Status.APPROVED,
        )
        RuleExclusion.objects.create(
            name="expired-rule",
            kind=RuleExclusion.Kind.REMOVE_RULE,
            rule_id=930100,
            rationale="Expired",
            owner="operations",
            status=RuleExclusion.Status.APPROVED,
            expires_at=timezone.now() - timezone.timedelta(minutes=1),
        )

        bundle = render_policy()

        self.assertIn("SecRuleRemoveById 920350", bundle.after)
        self.assertNotIn("930100", bundle.after)


class ManagedPolicyDeploymentTests(SimpleTestCase):
    def _bundle(self, before="before\n", after="after\n"):
        return PolicyBundle(
            before=before,
            after=after,
            active_exclusions=0,
            active_address_entries=0,
            warnings=(),
        )

    @patch("wafinstaller.policy.subprocess.run")
    def test_deploys_both_files_then_validates_and_reloads(self, run):
        with TemporaryDirectory() as directory:
            changed = deploy_policy_bundle(
                self._bundle(),
                base_dir=Path(directory),
                test_cmd=["nginx", "-t"],
                reload_cmd=["nginx", "-s", "reload"],
                require_includes=False,
            )

            self.assertTrue(changed)
            self.assertEqual(Path(directory, BEFORE_FILENAME).read_text(), "before\n")
            self.assertEqual(Path(directory, AFTER_FILENAME).read_text(), "after\n")
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

    @patch("wafinstaller.policy.subprocess.run")
    def test_identical_bundle_does_not_validate_or_reload(self, run):
        with TemporaryDirectory() as directory:
            Path(directory, BEFORE_FILENAME).write_text("before\n")
            Path(directory, AFTER_FILENAME).write_text("after\n")

            changed = deploy_policy_bundle(
                self._bundle(),
                base_dir=Path(directory),
                test_cmd=["nginx", "-t"],
                reload_cmd=["nginx", "-s", "reload"],
                require_includes=False,
            )

            self.assertFalse(changed)
            run.assert_not_called()

    @patch("wafinstaller.policy.subprocess.run")
    def test_refuses_symlinked_managed_file(self, run):
        with TemporaryDirectory() as directory, TemporaryDirectory() as outside:
            external = Path(outside, "external.conf")
            external.write_text("do-not-touch\n")
            Path(directory, BEFORE_FILENAME).symlink_to(external)

            with self.assertRaises(PolicyDeploymentError):
                deploy_policy_bundle(
                    self._bundle(),
                    base_dir=Path(directory),
                    test_cmd=["nginx", "-t"],
                    reload_cmd=["nginx", "-s", "reload"],
                    require_includes=False,
                )

            self.assertEqual(external.read_text(), "do-not-touch\n")
            run.assert_not_called()

    @patch("wafinstaller.policy.subprocess.run")
    def test_failed_reload_restores_both_files(self, run):
        run.side_effect = [
            None,
            subprocess.CalledProcessError(1, ["nginx", "-s", "reload"]),
            None,
        ]
        with TemporaryDirectory() as directory:
            before = Path(directory, BEFORE_FILENAME)
            after = Path(directory, AFTER_FILENAME)
            before.write_text("old-before\n")
            after.write_text("old-after\n")

            with self.assertRaises(PolicyDeploymentError):
                deploy_policy_bundle(
                    self._bundle(),
                    base_dir=Path(directory),
                    test_cmd=["nginx", "-t"],
                    reload_cmd=["nginx", "-s", "reload"],
                    require_includes=False,
                )

            self.assertEqual(before.read_text(), "old-before\n")
            self.assertEqual(after.read_text(), "old-after\n")


class ManagedPolicyViewTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="policy-admin",
            password="test-password",
            is_staff=True,
            is_superuser=True,
        )

    def test_policy_page_requires_authentication(self):
        response = self.client.get(reverse("wafinstaller:policy_management"))
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login/", response.url)

    def test_mutations_reject_missing_csrf_token(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        routes = (
            ("wafinstaller:address_list_create", ()),
            ("wafinstaller:address_entry_create", ()),
            ("wafinstaller:rule_exclusion_create", ()),
            (
                "wafinstaller:policy_object_mutation",
                ("address-list", 1, "delete"),
            ),
            ("wafinstaller:policy_deploy", ()),
        )
        for route_name, args in routes:
            with self.subTest(route_name=route_name):
                response = client.post(reverse(route_name, args=args))
                self.assertEqual(response.status_code, 403)

    def test_creates_address_list_and_records_audit(self):
        self.client.force_login(self.user)
        response = self.client.post(
            reverse("wafinstaller:address_list_create"),
            {
                "name": "known-scanners",
                "purpose": AddressList.Purpose.OBSERVE,
                "description": "Observe known research scanners",
                "enabled": "on",
            },
        )

        self.assertRedirects(response, reverse("wafinstaller:policy_management"))
        address_list = AddressList.objects.get(name="known-scanners")
        self.assertEqual(address_list.created_by, self.user)
        audit = AuditEntry.objects.get(action="policy.address_list.create")
        self.assertEqual(audit.outcome, AuditEntry.Outcome.SUCCEEDED)


class PolicyApprovalWorkflowTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="approver",
            password="test-password",
            is_staff=True,
            is_superuser=True,
        )

    def test_draft_tag_exclusion_is_not_rendered_until_approved(self):
        exclusion = RuleExclusion.objects.create(
            name="sqli-tag-compatibility",
            kind=RuleExclusion.Kind.REMOVE_RULE,
            rule_tag="attack-sqli",
            rationale="Compatibility review",
            owner="security",
        )

        self.assertNotIn("attack-sqli", render_policy().after)

        exclusion.status = RuleExclusion.Status.APPROVED
        exclusion.save(update_fields=("status", "updated_at"))

        self.assertIn("SecRuleRemoveByTag attack-sqli", render_policy().after)

    def test_approval_is_explicit_and_audited(self):
        exclusion = RuleExclusion.objects.create(
            name="approved-through-ui",
            kind=RuleExclusion.Kind.REMOVE_RULE,
            rule_id=920350,
            rationale="Reviewed false positive",
            owner="security",
        )
        self.client.force_login(self.user)

        response = self.client.post(
            reverse(
                "wafinstaller:policy_object_mutation",
                args=("rule-exclusion", exclusion.pk, "approve"),
            )
        )

        self.assertRedirects(response, reverse("wafinstaller:policy_management"))
        exclusion.refresh_from_db()
        self.assertEqual(exclusion.status, RuleExclusion.Status.APPROVED)
        audit = AuditEntry.objects.get(action="policy.object.mutate")
        self.assertEqual(audit.outcome, AuditEntry.Outcome.SUCCEEDED)

    @patch("wafinstaller.policy_views.include_status", return_value=False)
    def test_authenticated_policy_page_renders_preview(self, _include_status):
        self.client.force_login(self.user)

        response = self.client.get(reverse("wafinstaller:policy_management"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Candidate policy and deployment diff")
        self.assertContains(response, "Deployment is disabled")

    @patch("wafinstaller.policy_views.include_status", return_value=False)
    def test_event_prefills_a_draft_exclusion(self, _include_status):
        attack = Attack.objects.create(
            country="France",
            flag="fr",
            rule_id="942100",
            message="SQL injection pattern",
            uri="/api/contact?source=test",
            status="Detected",
            version="4.28.0",
            host="ironitia.com",
        )
        self.client.force_login(self.user)

        response = self.client.get(
            reverse("wafinstaller:policy_management"),
            {"attack": attack.pk},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f"Draft prefilled from event #{attack.pk}")
        self.assertContains(response, 'value="942100"')
        self.assertContains(response, 'value="/api/contact"')


class ManagedPolicyInstallerTests(SimpleTestCase):
    def test_installer_rejects_unsafe_directory_before_privileged_actions(self):
        script = (
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "install_managed_policy.sh"
        )

        result = subprocess.run(
            ["/bin/bash", str(script), "/etc/nginx/modsec/../../tmp"],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 2)
        self.assertIn("safe absolute path", result.stdout)
