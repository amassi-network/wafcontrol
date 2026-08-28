import os
import subprocess
import syslog
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import call, patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.staticfiles import finders
from django.core.exceptions import ValidationError
from django.test import Client, SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from wafinstaller.attacks import attack_apache, attack_nginx
from wafinstaller.models import (
    AddressEntry,
    AddressList,
    Application,
    Attack,
    AuditEntry,
    ConfigRevision,
    Policy,
    PolicyBinding,
    PolicyRevision,
    RuleExclusion,
    TriageDecision,
)
from wafinstaller.policy import (
    AFTER_FILENAME,
    BEFORE_FILENAME,
    PolicyBundle,
    PolicyDeploymentError,
    deploy_policy_bundle,
    effective_policy_snapshot,
    render_policy,
)
from wafinstaller.security_events import emit_attack_syslog, format_attack_syslog
from wafinstaller.tasks import (
    _attack_already_seen,
    _connection_metadata,
    expire_managed_policy_objects,
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
    def test_installer_uses_the_deterministic_crs_renderer(self):
        script = (
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "install_managed_policy.sh"
        )

        contents = script.read_text()

        self.assertIn("render_nginx_crs_main.sh", contents)
        self.assertIn("crs-setup", contents)

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


class PolicyLot3BTests(TestCase):
    def setUp(self):
        self.author = get_user_model().objects.create_user(
            username="author", password="password", is_staff=True
        )
        self.approver = get_user_model().objects.create_user(
            username="approver-3b", password="password", is_staff=True
        )

    def _attack(self):
        return Attack.objects.create(
            country="France",
            flag="fr",
            rule_id="942100",
            message="Matched Data",
            uri="/api/contact",
            status="Blocked",
            version="4.28.0",
            method="POST",
            transaction_id="tx-123",
            matched_variable="ARGS:description",
            rule_tags=["attack-sqli"],
        )

    def test_event_triage_is_created_and_audited(self):
        attack = self._attack()
        self.client.force_login(self.author)
        response = self.client.post(
            reverse("wafinstaller:event_triage", args=(attack.pk,)),
            {
                "classification": TriageDecision.Classification.FALSE_POSITIVE,
                "notes": "Reproduced with valid business input.",
            },
        )
        self.assertRedirects(response, reverse("wafinstaller:waf_attacks"))
        decision = TriageDecision.objects.get(attack=attack)
        self.assertEqual(decision.decided_by, self.author)
        self.assertTrue(AuditEntry.objects.filter(action="event.triage").exists())

    def test_policy_revision_content_is_immutable(self):
        revision = PolicyRevision.objects.create(
            checksum=sha256(b"before\0after").hexdigest(),
            before_content="before",
            after_content="after",
            created_by=self.author,
        )
        revision.before_content = "changed"
        with self.assertRaises(ValidationError):
            revision.save()

    @override_settings(WAFCONTROL_REQUIRE_SEPARATE_APPROVER=True)
    def test_revision_requires_a_different_approver(self):
        revision = PolicyRevision.objects.create(
            checksum=sha256(b"before\0after").hexdigest(),
            before_content="before",
            after_content="after",
            created_by=self.author,
        )
        self.client.force_login(self.author)
        self.client.post(
            reverse(
                "wafinstaller:policy_revision_mutation",
                args=(revision.pk, "approve"),
            )
        )
        revision.refresh_from_db()
        self.assertEqual(revision.status, PolicyRevision.Status.CANDIDATE)

        self.client.force_login(self.approver)
        self.client.post(
            reverse(
                "wafinstaller:policy_revision_mutation",
                args=(revision.pk, "approve"),
            )
        )
        revision.refresh_from_db()
        self.assertEqual(revision.status, PolicyRevision.Status.APPROVED)
        self.assertEqual(revision.approved_by, self.approver)

    def test_expiry_task_disables_objects_and_records_audit(self):
        address_list = AddressList.objects.create(
            name="temporary-scanners",
            purpose=AddressList.Purpose.OBSERVE,
            description="Temporary observation",
        )
        entry = AddressEntry.objects.create(
            address_list=address_list,
            network="192.0.2.1/32",
            comment="Expired",
            expires_at=timezone.now() - timezone.timedelta(minutes=1),
        )
        exclusion = RuleExclusion.objects.create(
            name="temporary-exclusion",
            kind=RuleExclusion.Kind.REMOVE_RULE,
            rule_id=920350,
            rationale="Temporary",
            owner="security",
            status=RuleExclusion.Status.APPROVED,
            expires_at=timezone.now() - timezone.timedelta(minutes=1),
        )

        result = expire_managed_policy_objects()

        entry.refresh_from_db()
        exclusion.refresh_from_db()
        self.assertFalse(entry.enabled)
        self.assertFalse(exclusion.enabled)
        self.assertEqual(result, {"address_entries": 1, "rule_exclusions": 1})
        self.assertTrue(AuditEntry.objects.filter(action="policy.expiry.run").exists())


class ModSecurityEventRegressionTests(SimpleTestCase):
    def test_extracts_method_transaction_tags_and_precise_variable(self):
        raw = """---tx-123-B--
POST /api/contact HTTP/1.1
Host: ironitia.com
---tx-123-H--
ModSecurity: Warning. Matched Data: select found within ARGS:description [id "942100"] [tag "attack-sqli"] [unique_id "tx-123"]
"""
        sections_by_backend = (
            attack_nginx.split_sections_lenient(raw),
            attack_apache.split_sections_lenient(raw),
        )
        for backend, sections in zip(
            (attack_nginx, attack_apache), sections_by_backend, strict=True
        ):
            with self.subTest(backend=backend.__name__):
                self.assertEqual(backend.method_from_B_sections(sections), "POST")
                self.assertEqual(
                    backend.extract_first(backend.MATCHED_VAR_RE, raw),
                    "ARGS:description",
                )
                self.assertEqual(
                    backend.extract_all(backend.TAGS_RE, raw), ["attack-sqli"]
                )
                self.assertEqual(backend.extract_first(backend.UID_RE, raw), "tx-123")


    def test_keeps_primary_rules_and_suppresses_only_summaries(self):
        hits = [
            ("913100", "scanner"),
            ("920350", "protocol"),
            ("100001", "custom"),
            ("949110", "inbound summary"),
            ("959100", "outbound summary"),
            ("980170", "correlation"),
            ("100002", "WAFControl_deployment_probe"),
        ]
        expected = hits[:3]
        for backend in (attack_apache, attack_nginx):
            with self.subTest(backend=backend.__name__):
                self.assertEqual(backend.filter_rule_hits(hits), expected)
                self.assertIsNone(
                    backend.pick_best_target("192.0.2.10", "/expected", ["/unrelated"])
                )

    def test_error_logs_are_grouped_by_transaction_with_metadata_preserved(self):
        raw = (
            '[security2:error] [client 192.0.2.10:4444] ModSecurity: Warning. '
            '[id "920350"] [msg "Numeric host"] [hostname "example.test"] '
            '[uri "/cgi-bin/test"] [unique_id "tx-error-1"]\n'
            '[security2:error] [client 192.0.2.10:4444] ModSecurity: Warning. '
            '[id "920420"] [msg "Invalid content type"] [hostname "example.test"] '
            '[uri "/cgi-bin/test"] [unique_id "tx-error-1"]\n'
        )
        with TemporaryDirectory() as directory:
            error_log = Path(directory) / "error.log"
            error_log.write_text(raw)
            for backend in (attack_apache, attack_nginx):
                with self.subTest(backend=backend.__name__):
                    blocks = backend.blocks_from_errorlogs([str(error_log)])
                    self.assertEqual(len(blocks), 1)
                    self.assertIn('[hostname "example.test"]', blocks[0])
                    self.assertEqual(backend.extract_first(backend.UID_RE, blocks[0]), "tx-error-1")
                    self.assertEqual(backend.IP_FALLBACKS[0].search(blocks[0]).group(1), "192.0.2.10")

class StaticFilesConfigurationTests(SimpleTestCase):
    def test_static_sources_are_separate_from_collection_target(self):
        source_directory = Path(settings.STATICFILES_DIRS[0]).resolve()
        collection_directory = Path(settings.STATIC_ROOT).resolve()

        self.assertNotEqual(source_directory, collection_directory)
        self.assertFalse(collection_directory.is_relative_to(source_directory))
        self.assertIsNotNone(finders.find("dashboard/css/style.css"))
        self.assertIsNotNone(finders.find("dashboard/js/jquery.min.js"))


class ApplicationPolicyMilestoneTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_user(
            username="application-policy-admin",
            password="test-password",
            is_staff=True,
            is_superuser=True,
        )

    def _binding(self):
        parent = Policy.objects.create(
            name="observe-baseline",
            engine_mode=Policy.EngineMode.DETECTION_ONLY,
            paranoia_level=2,
            inbound_threshold=7,
            outbound_threshold=4,
        )
        child = Policy.objects.create(
            name="ironitia-web",
            parent=parent,
            outbound_threshold=6,
        )
        application = Application.objects.create(
            name="Ironitia",
            hostname="ironitia.com",
        )
        binding = PolicyBinding(
            application=application,
            policy=child,
            overrides={"paranoia_level": 3},
        )
        binding.full_clean()
        binding.save()
        return parent, child, application, binding

    def test_policy_inheritance_and_binding_overrides_are_resolved(self):
        _parent, child, _application, binding = self._binding()

        self.assertEqual(
            child.effective_config(),
            {
                "engine_mode": Policy.EngineMode.DETECTION_ONLY,
                "paranoia_level": 2,
                "inbound_threshold": 7,
                "outbound_threshold": 6,
            },
        )
        self.assertEqual(binding.effective_config()["paranoia_level"], 3)

    def test_policy_cycle_and_invalid_override_are_rejected(self):
        parent, child, _application, binding = self._binding()
        parent.parent = child
        with self.assertRaises(ValidationError):
            parent.full_clean()

        binding.overrides = {"paranoia_level": "invalid"}
        with self.assertRaises(ValidationError):
            binding.full_clean()

        binding.overrides = {"paranoia_level": 8}
        with self.assertRaises(ValidationError):
            binding.full_clean()

    def test_application_policy_is_rendered_before_crs(self):
        self._binding()

        bundle = render_policy()

        self.assertEqual(bundle.active_applications, 1)
        self.assertIn("Application: Ironitia", bundle.before)
        self.assertIn("@streq ironitia.com", bundle.before)
        self.assertIn("ctl:ruleEngine=DetectionOnly", bundle.before)
        self.assertIn("setvar:tx.paranoia_level=3", bundle.before)
        self.assertIn("setvar:tx.inbound_anomaly_score_threshold=7", bundle.before)
        self.assertIn("setvar:tx.outbound_anomaly_score_threshold=6", bundle.before)

    def test_configuration_snapshot_and_revision_are_immutable(self):
        self._binding()
        snapshot = effective_policy_snapshot()
        config = ConfigRevision.objects.create(
            checksum=ConfigRevision.checksum_for(snapshot),
            snapshot=snapshot,
            created_by=self.user,
        )
        config.snapshot = {"schema": 999}
        with self.assertRaises(ValidationError):
            config.save()

    def test_candidate_links_frozen_configuration_snapshot(self):
        self._binding()
        self.client.force_login(self.user)

        response = self.client.post(reverse("wafinstaller:policy_revision_create"))

        self.assertRedirects(response, reverse("wafinstaller:policy_management"))
        revision = PolicyRevision.objects.get()
        self.assertIsNotNone(revision.config_revision)
        self.assertEqual(revision.summary["active_applications"], 1)
        self.assertEqual(
            revision.summary["config_checksum"],
            revision.config_revision.checksum,
        )

    @patch("wafinstaller.policy_views.include_status", return_value=False)
    def test_policy_management_renders_effective_configuration(self, _include_status):
        self._binding()
        self.client.force_login(self.user)

        response = self.client.get(reverse("wafinstaller:policy_management"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Applications and effective policies")
        self.assertContains(response, "Detection only")
        self.assertContains(response, "thresholds 7/6")

    def test_new_mutation_routes_require_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        for route_name in (
            "wafinstaller:application_create",
            "wafinstaller:waf_policy_create",
            "wafinstaller:policy_binding_create",
        ):
            with self.subTest(route_name=route_name):
                response = client.post(reverse(route_name))
                self.assertEqual(response.status_code, 403)


class SyslogSecurityEventTests(SimpleTestCase):
    def _attack(self, **overrides):
        values = {
            "rule_id": "942100",
            "message": "SQL Injection Attack Detected via libinjection",
            "status": "Blocked",
            "severity": 3,
            "rule_tags": ["attack-sqli"],
            "protocol": "TCP",
            "ip": "34.34.254.214",
            "source_port": 4575,
            "destination_ip": "46.28.168.244",
            "destination_port": 443,
        }
        values.update(overrides)
        return SimpleNamespace(**values)

    def test_formats_snort_compatible_network_tuple(self):
        message = format_attack_syslog(self._attack())

        self.assertEqual(
            message,
            "[1:942100:1] MODSEC SQL Injection Attack Detected via libinjection "
            "[Classification: Web Application SQL Injection] [Priority: 1] "
            "{TCP} 34.34.254.214:4575 -> 46.28.168.244:443",
        )

    @patch("wafinstaller.security_events.os.path.exists", return_value=False)
    @patch("wafinstaller.security_events.syslog.syslog")
    @patch("wafinstaller.security_events.syslog.openlog")
    def test_emits_each_alert_to_local5_syslog(self, openlog, send, _exists):
        attack = self._attack(status="High", severity=2)

        emit_attack_syslog(attack)

        openlog.assert_called_once_with(
            "wafcontrol",
            syslog.LOG_PID,
            syslog.LOG_LOCAL5,
        )
        send.assert_called_once()
        self.assertEqual(send.call_args.args[0], syslog.LOG_WARNING)

    @patch("wafinstaller.security_events.os.path.exists", return_value=True)
    @patch("wafinstaller.security_events.socket.socket")
    def test_emits_over_dedicated_flow_control_socket(self, socket_factory, _exists):
        attack = self._attack(status="High", severity=2)

        result = emit_attack_syslog(attack)

        transport = socket_factory.return_value.__enter__.return_value
        self.assertEqual(result, "dedicated")
        transport.connect.assert_called_once_with("/run/wafcontrol-rsyslog/syslog.sock")
        payload = transport.sendall.call_args.args[0]
        self.assertTrue(payload.startswith(b"<172>wafcontrol["))
        self.assertIn(b"[1:942100:1] MODSEC", payload)

    def test_classifies_by_crs_family_before_transaction_tags(self):
        attack = self._attack(
            rule_id="932235",
            message="Remote Command Execution",
            rule_tags=["attack-sqli", "attack-rce"],
        )

        self.assertIn(
            "[Classification: Remote Command Execution]",
            format_attack_syslog(attack),
        )

    def test_extracts_complete_modsecurity_network_tuple(self):
        sections = {
            "A": [
                "[22/Aug/2026:03:40:12 +0000] txid 34.34.254.214 4575 46.28.168.244 443"
            ]
        }

        metadata = _connection_metadata(attack_nginx, sections)

        self.assertEqual(
            metadata,
            {
                "source_port": 4575,
                "destination_ip": "46.28.168.244",
                "destination_port": 443,
                "protocol": "TCP",
            },
        )


class SyslogAttackDeduplicationTests(TestCase):
    def test_same_signature_with_different_transaction_is_not_suppressed(self):
        common = {
            "ip": "34.34.254.214",
            "uri": "/.env",
            "host": "ironitia.com",
            "rule_id": "930120",
            "message": "OS File Access Attempt",
            "version": "OWASP_CRS/4.28.0",
            "status": "Blocked",
        }
        Attack.objects.create(
            **common,
            country="-",
            flag="-",
            transaction_id="transaction-one",
        )

        self.assertTrue(
            _attack_already_seen(
                "transaction-one",
                **common,
            )
        )
        self.assertFalse(
            _attack_already_seen(
                "transaction-two",
                **common,
            )
        )


class NginxCrsIncludeOrderTests(SimpleTestCase):
    def test_renderer_keeps_managed_files_around_crs(self):
        script = (
            Path(__file__).resolve().parents[1] / "scripts" / "render_nginx_crs_main.sh"
        )
        with TemporaryDirectory() as directory:
            root = Path(directory)
            policy_dir = root / "policy"
            policy_dir.mkdir()
            before = policy_dir / "REQUEST-890-WAFCONTROL-BEFORE.conf"
            after = policy_dir / "RESPONSE-990-WAFCONTROL-AFTER.conf"
            before.touch()
            after.touch()
            current = root / "main.conf"
            output = root / "candidate.conf"
            old_crs = root / "coreruleset-4.28.0"
            new_crs = root / "coreruleset-4.29.0"
            current.write_text(
                "Include /etc/nginx/modsec/modsecurity.conf\n"
                "Include /etc/nginx/modsec/site-before-crs.conf\n"
                f"Include {before}\n"
                f"Include {after}\n"
                f"Include {old_crs}/crs-setup.conf\n"
                f"Include {old_crs}/rules/*.conf\n"
            )

            result = subprocess.run(
                [str(script), str(current), str(new_crs), str(output)],
                env={
                    **os.environ,
                    "WAFCONTROL_POLICY_DIR": str(policy_dir),
                },
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            lines = output.read_text().splitlines()
            self.assertLess(
                lines.index(f"Include {before}"),
                lines.index(f"Include {new_crs}/crs-setup.conf"),
            )
            self.assertLess(
                lines.index(f"Include {new_crs}/rules/*.conf"),
                lines.index(f"Include {after}"),
            )
            self.assertNotIn(str(old_crs), output.read_text())


class DeploymentConfigRendererTests(SimpleTestCase):
    def setUp(self):
        self.script = (
            Path(__file__).resolve().parents[1]
            / "scripts"
            / "render_deployment_config.sh"
        )
        self.site_environment = {
            **os.environ,
            "WAF_DOMAIN": "waf.example.net",
            "WAF_PUBLIC_IP": "192.0.2.10",
            "WAF_PUBLIC_IPV6": "2001:db8::10",
            "WAF_ADMIN_ALLOW_IP": (
                "198.51.100.8/32,203.0.113.9/32,2001:db8:1::/64"
            ),
            "WAF_CRS_VERSION": "4.29.0",
            "WAF_MAPATTACK_HOST": "192.0.2.20",
            "WAF_MAPATTACK_PORT": "514",
        }

    def test_renderer_produces_complete_site_bundle(self):
        with TemporaryDirectory() as directory:
            output = Path(directory) / "rendered"
            result = subprocess.run(
                [str(self.script), str(output)],
                env=self.site_environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            expected = {
                "wafcontrol.env",
                "modsecurity/main.conf",
                "modsecurity/site-before-crs.conf",
                "nginx/site-modsecurity.conf.snippet",
                "nginx/wafcontrol-admin.conf",
                "rsyslog/60-wafcontrol-mapattack.conf",
                "systemd/wafcontrol.service",
                "systemd/wafcontrol-celery-worker.service",
                "systemd/wafcontrol-celery-beat.service",
                "systemd/wafcontrol-backup.service",
                "systemd/wafcontrol-backup.timer",
            }
            self.assertEqual(
                expected,
                {
                    str(path.relative_to(output))
                    for path in output.rglob("*")
                    if path.is_file()
                },
            )
            rendered = "\n".join(
                path.read_text() for path in output.rglob("*") if path.is_file()
            )
            self.assertNotIn("@@", rendered)
            admin_vhost = (
                output / "nginx" / "wafcontrol-admin.conf"
            ).read_text()
            self.assertIn("listen [2001:db8::10]:7000 ssl;", admin_vhost)
            self.assertIn("allow 198.51.100.8/32;", admin_vhost)
            self.assertIn("allow 203.0.113.9/32;", admin_vhost)
            self.assertIn("allow 2001:db8:1::/64;", admin_vhost)
            self.assertIn("WEBAUTHN_RP_ID=waf.example.net", rendered)
            self.assertIn(
                "WEBAUTHN_ALLOWED_ORIGINS=https://waf.example.net:7000",
                rendered,
            )
            self.assertIn('target="192.0.2.20"', rendered)
            includes = (output / "modsecurity" / "main.conf").read_text().splitlines()
            self.assertLess(
                includes.index(
                    "Include /etc/nginx/modsec/wafcontrol/"
                    "REQUEST-890-WAFCONTROL-BEFORE.conf"
                ),
                includes.index(
                    "Include /etc/nginx/modsec/coreruleset-4.29.0/crs-setup.conf"
                ),
            )
            self.assertLess(
                includes.index(
                    "Include /etc/nginx/modsec/coreruleset-4.29.0/rules/*.conf"
                ),
                includes.index(
                    "Include /etc/nginx/modsec/wafcontrol/"
                    "RESPONSE-990-WAFCONTROL-AFTER.conf"
                ),
            )
            self.assertEqual((output / "wafcontrol.env").stat().st_mode & 0o777, 0o600)

            env_file = output / "wafcontrol.env"
            env_file.write_text(
                env_file.read_text()
                .replace("[GENERATE A UNIQUE SECRET]", "test-secret")
                .replace("[TO BE COMPLETED]", "test-value")
            )
            sourced = subprocess.run(
                [
                    "bash",
                    "-eu",
                    "-c",
                    '. "$1"; printf "%s" "$WEBAUTHN_RP_NAME"',
                    "bash",
                    str(env_file),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(sourced.returncode, 0, sourced.stderr)
            self.assertEqual(sourced.stdout, "OWASP WAFControl")

    def test_renderer_refuses_missing_required_input(self):
        environment = self.site_environment.copy()
        environment.pop("WAF_ADMIN_ALLOW_IP")
        with TemporaryDirectory() as directory:
            result = subprocess.run(
                [str(self.script), str(Path(directory) / "rendered")],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 2)
        self.assertIn("WAF_ADMIN_ALLOW_IP", result.stderr)

    def test_renderer_omits_optional_ipv6_listener(self):
        environment = self.site_environment.copy()
        environment.pop("WAF_PUBLIC_IPV6")
        with TemporaryDirectory() as directory:
            output = Path(directory) / "rendered"
            result = subprocess.run(
                [str(self.script), str(output)],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            admin_vhost = (
                output / "nginx" / "wafcontrol-admin.conf"
            ).read_text()
            self.assertNotIn("listen [", admin_vhost)
            self.assertNotIn("@@PUBLIC_IPV6_LISTEN@@", admin_vhost)

    def test_renderer_refuses_invalid_admin_address_lists(self):
        invalid_lists = (
            "198.51.100.8/32,,203.0.113.9/32",
            "999.51.100.8/32",
            "198.51.100.8/32;deny",
            "2001:db8::/129",
        )
        for invalid_list in invalid_lists:
            with self.subTest(invalid_list=invalid_list):
                environment = {
                    **self.site_environment,
                    "WAF_ADMIN_ALLOW_IP": invalid_list,
                }
                with TemporaryDirectory() as directory:
                    result = subprocess.run(
                        [str(self.script), str(Path(directory) / "rendered")],
                        env=environment,
                        capture_output=True,
                        text=True,
                        check=False,
                    )

                self.assertEqual(result.returncode, 2)
                self.assertIn("administration address/CIDR", result.stdout)

    def test_renderer_refuses_invalid_public_addresses(self):
        invalid_values = (
            ("WAF_PUBLIC_IP", "192.0.2.999"),
            ("WAF_PUBLIC_IPV6", "2001:db8::10/64"),
        )
        for name, value in invalid_values:
            with self.subTest(name=name):
                environment = {**self.site_environment, name: value}
                with TemporaryDirectory() as directory:
                    result = subprocess.run(
                        [str(self.script), str(Path(directory) / "rendered")],
                        env=environment,
                        capture_output=True,
                        text=True,
                        check=False,
                    )

                self.assertEqual(result.returncode, 2)
