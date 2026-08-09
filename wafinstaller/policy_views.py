from datetime import timedelta
from hashlib import sha256
from typing import ClassVar
from urllib.parse import urlsplit

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import transaction
from django.db.models import Q
from django.db.models.deletion import ProtectedError
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views import View
from django.views.generic import TemplateView

from wafinstaller.audit import AuditedMutationMixin, mark_audit_failure
from wafinstaller.helper.adapters import get_paths
from wafinstaller.models import (
    AddressEntry,
    AddressList,
    Application,
    Attack,
    ConfigRevision,
    Policy,
    PolicyBinding,
    PolicyRevision,
    RuleExclusion,
)
from wafinstaller.policy import (
    PolicyBundle,
    PolicyDeploymentError,
    deploy_policy_bundle,
    effective_policy_snapshot,
    include_directives,
    include_status,
    policy_diff,
    render_policy,
)
from wafinstaller.policy_forms import (
    AddressEntryForm,
    AddressListForm,
    ApplicationForm,
    PolicyBindingForm,
    PolicyForm,
    RuleExclusionForm,
)


def _report_form_errors(request, form):
    for field, errors in form.errors.items():
        label = form.fields[field].label if field in form.fields else "Form"
        for error in errors:
            messages.error(request, f"{label}: {error}")


class PolicyManagementView(LoginRequiredMixin, TemplateView):
    login_url = "wafinstaller:login"
    template_name = "dashboard/panel/policy_management.html"

    def _exclusion_initial(self):
        attack_id = self.request.GET.get("attack")
        if not attack_id or not attack_id.isdigit():
            return {}, None
        attack = Attack.objects.filter(pk=attack_id).first()
        if attack is None:
            return {}, None
        rule_id = int(attack.rule_id) if attack.rule_id.isdigit() else None
        host = (attack.host or "").split(":", 1)[0]
        initial = {
            "name": f"event-{attack.pk}-rule-{attack.rule_id}"[:120],
            "kind": RuleExclusion.Kind.REMOVE_TARGET
            if attack.matched_variable
            else RuleExclusion.Kind.REMOVE_RULE,
            "rule_id": rule_id,
            "target": attack.matched_variable,
            "host": host,
            "method": attack.method,
            "path": urlsplit(attack.uri).path or "/",
            "path_match": RuleExclusion.PathMatch.EXACT,
            "rationale": (
                f"Draft proposed from WAF event #{attack.pk}; review before approval."
            ),
            "owner": self.request.user.get_full_name() or self.request.user.username,
            "enabled": True,
        }
        return initial, attack

    @staticmethod
    def _impact_count(exclusion):
        if not exclusion.rule_id:
            return None
        events = Attack.objects.filter(rule_id=str(exclusion.rule_id))
        if exclusion.host:
            events = events.filter(host__iexact=exclusion.host)
        if exclusion.path:
            if exclusion.path_match == RuleExclusion.PathMatch.EXACT:
                events = events.filter(
                    Q(uri=exclusion.path) | Q(uri__startswith=f"{exclusion.path}?")
                )
            else:
                events = events.filter(uri__startswith=exclusion.path)
        suspicious = events.filter(Q(status="Blocked") | Q(severity__gte=3)).count()
        return {"total": events.count(), "suspicious": suspicious}

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        bundle = render_policy()
        initial, source_attack = self._exclusion_initial()
        exclusions = list(RuleExclusion.objects.all())
        edit_id = self.request.GET.get("edit")
        edit_exclusion = RuleExclusion.objects.filter(pk=edit_id).first()
        if edit_exclusion:
            initial = None
        moment = timezone.now()
        expiry_deadline = moment + timedelta(days=7)
        expiring_exclusions = RuleExclusion.objects.filter(
            enabled=True, expires_at__gt=moment, expires_at__lte=expiry_deadline
        )
        expiring_entries = AddressEntry.objects.filter(
            enabled=True, expires_at__gt=moment, expires_at__lte=expiry_deadline
        )
        bindings = list(
            PolicyBinding.objects.select_related("application", "policy").all()
        )
        for binding in bindings:
            binding.resolved_config = binding.effective_config()
        for exclusion in exclusions:
            exclusion.impact_count = self._impact_count(exclusion)
        context.update(
            {
                "address_lists": AddressList.objects.prefetch_related("entries").all(),
                "exclusions": exclusions,
                "address_list_form": AddressListForm(),
                "address_entry_form": AddressEntryForm(),
                "applications": Application.objects.select_related(
                    "policy_binding__policy"
                ).all(),
                "policies": Policy.objects.select_related("parent").all(),
                "bindings": bindings,
                "application_form": ApplicationForm(),
                "policy_form": PolicyForm(),
                "binding_form": PolicyBindingForm(),
                "exclusion_form": RuleExclusionForm(
                    instance=edit_exclusion, initial=initial
                ),
                "source_attack": source_attack,
                "policy_bundle": bundle,
                "policy_diff": policy_diff(bundle),
                "include_status": include_status(),
                "include_directives": include_directives(),
                "edit_exclusion": edit_exclusion,
                "revisions": PolicyRevision.objects.select_related(
                    "created_by", "approved_by", "config_revision"
                )[:20],
                "separate_approver": settings.WAFCONTROL_REQUIRE_SEPARATE_APPROVER,
                "now": moment,
                "expiring_exclusions": expiring_exclusions,
                "expiring_entries": expiring_entries,
            }
        )
        return context


class AddressListCreateView(AuditedMutationMixin, LoginRequiredMixin, View):
    login_url = "wafinstaller:login"
    audit_action = "policy.address_list.create"

    def post(self, request):
        form = AddressListForm(request.POST)
        if form.is_valid():
            address_list = form.save(commit=False)
            address_list.created_by = request.user
            address_list.save()
            messages.success(request, f"Address list {address_list.name} created.")
        else:
            mark_audit_failure(request)
            _report_form_errors(request, form)
        return redirect("wafinstaller:policy_management")


class AddressEntryCreateView(AuditedMutationMixin, LoginRequiredMixin, View):
    login_url = "wafinstaller:login"
    audit_action = "policy.address_entry.create"

    def post(self, request):
        form = AddressEntryForm(request.POST)
        if form.is_valid():
            entry = form.save(commit=False)
            entry.created_by = request.user
            entry.save()
            messages.success(request, f"Address entry {entry.network} created.")
        else:
            mark_audit_failure(request)
            _report_form_errors(request, form)
        return redirect("wafinstaller:policy_management")


class RuleExclusionCreateView(AuditedMutationMixin, LoginRequiredMixin, View):
    login_url = "wafinstaller:login"
    audit_action = "policy.rule_exclusion.create"

    def post(self, request):
        form = RuleExclusionForm(request.POST)
        if form.is_valid():
            exclusion = form.save(commit=False)
            exclusion.created_by = request.user
            exclusion.save()
            messages.success(request, f"Rule exclusion {exclusion.name} created.")
        else:
            mark_audit_failure(request)
            _report_form_errors(request, form)
        return redirect("wafinstaller:policy_management")


class PolicyObjectMutationView(AuditedMutationMixin, LoginRequiredMixin, View):
    login_url = "wafinstaller:login"
    audit_action = "policy.object.mutate"
    models: ClassVar[dict[str, type]] = {
        "address-list": AddressList,
        "address-entry": AddressEntry,
        "rule-exclusion": RuleExclusion,
        "application": Application,
        "policy": Policy,
        "policy-binding": PolicyBinding,
    }

    def post(self, request, object_type, object_id, operation):
        model = self.models.get(object_type)
        if model is None or operation not in {"toggle", "approve", "delete", "clone"}:
            mark_audit_failure(request)
            messages.error(request, "Unsupported policy operation.")
            return redirect("wafinstaller:policy_management")

        instance = get_object_or_404(model, pk=object_id)
        if operation == "delete":
            label = str(instance)
            try:
                instance.delete()
            except ProtectedError:
                mark_audit_failure(request)
                messages.error(
                    request,
                    f"{label} is still referenced and cannot be deleted.",
                )
            else:
                messages.success(request, f"{label} deleted.")
        elif operation == "clone" and isinstance(instance, RuleExclusion):
            source_id = instance.pk
            instance.pk = None
            instance.name = f"{instance.name}-copy-{source_id}"
            instance.status = RuleExclusion.Status.DRAFT
            instance.created_by = request.user
            instance.approved_by = None
            instance.approved_at = None
            instance.save()
            messages.success(request, f"Draft {instance.name} cloned.")
        elif operation == "approve" and isinstance(instance, RuleExclusion):
            instance.status = (
                RuleExclusion.Status.DRAFT
                if instance.status == RuleExclusion.Status.APPROVED
                else RuleExclusion.Status.APPROVED
            )
            if (
                instance.status == RuleExclusion.Status.APPROVED
                and settings.WAFCONTROL_REQUIRE_SEPARATE_APPROVER
                and instance.created_by_id == request.user.id
            ):
                mark_audit_failure(request)
                messages.error(request, "A different user must approve this exclusion.")
                return redirect("wafinstaller:policy_management")
            instance.approved_by = (
                request.user
                if instance.status == RuleExclusion.Status.APPROVED
                else None
            )
            instance.approved_at = (
                timezone.now()
                if instance.status == RuleExclusion.Status.APPROVED
                else None
            )
            instance.save(
                update_fields=("status", "approved_by", "approved_at", "updated_at")
            )
            messages.success(
                request, f"{instance} is now {instance.get_status_display()}."
            )
        elif operation == "toggle":
            instance.enabled = not instance.enabled
            instance.save(update_fields=("enabled", "updated_at"))
            messages.success(
                request,
                f"{instance} {'enabled' if instance.enabled else 'disabled'}.",
            )
        else:
            mark_audit_failure(request)
            messages.error(
                request, "This operation is not valid for the selected object."
            )
        return redirect("wafinstaller:policy_management")


class PolicyDeployView(AuditedMutationMixin, LoginRequiredMixin, View):
    login_url = "wafinstaller:login"
    audit_action = "policy.deploy"

    def post(self, request):
        mark_audit_failure(request)
        messages.error(
            request,
            "Direct deployment is disabled. Freeze and approve a revision first.",
        )
        return redirect("wafinstaller:policy_management")


class RuleExclusionUpdateView(AuditedMutationMixin, LoginRequiredMixin, View):
    login_url = "wafinstaller:login"
    audit_action = "policy.rule_exclusion.update"

    def post(self, request, object_id):
        exclusion = get_object_or_404(RuleExclusion, pk=object_id)
        form = RuleExclusionForm(request.POST, instance=exclusion)
        if form.is_valid():
            exclusion = form.save(commit=False)
            exclusion.status = RuleExclusion.Status.DRAFT
            exclusion.approved_by = None
            exclusion.approved_at = None
            exclusion.save()
            messages.success(
                request, f"{exclusion.name} updated and returned to draft."
            )
        else:
            mark_audit_failure(request)
            _report_form_errors(request, form)
        return redirect("wafinstaller:policy_management")


class PolicyRevisionCreateView(AuditedMutationMixin, LoginRequiredMixin, View):
    login_url = "wafinstaller:login"
    audit_action = "policy.revision.create"

    def post(self, request):
        snapshot = effective_policy_snapshot()
        config_checksum = ConfigRevision.checksum_for(snapshot)
        config_revision, _ = ConfigRevision.objects.get_or_create(
            checksum=config_checksum,
            defaults={
                "snapshot": snapshot,
                "created_by": request.user,
            },
        )
        bundle = render_policy()
        checksum = sha256(
            (bundle.before + "\0" + bundle.after).encode("utf-8")
        ).hexdigest()
        revision, created = PolicyRevision.objects.get_or_create(
            checksum=checksum,
            defaults={
                "before_content": bundle.before,
                "after_content": bundle.after,
                "created_by": request.user,
                "config_revision": config_revision,
                "summary": {
                    "active_exclusions": bundle.active_exclusions,
                    "active_address_entries": bundle.active_address_entries,
                    "warnings": list(bundle.warnings),
                    "active_applications": bundle.active_applications,
                    "config_checksum": config_checksum,
                },
            },
        )
        state = "created" if created else "already exists"
        if revision.config_revision_id is None:
            PolicyRevision.objects.filter(
                pk=revision.pk, config_revision__isnull=True
            ).update(config_revision=config_revision)
            revision.config_revision = config_revision
        messages.success(
            request, f"Candidate revision {revision.checksum[:12]} {state}."
        )
        return redirect("wafinstaller:policy_management")


class PolicyRevisionMutationView(AuditedMutationMixin, LoginRequiredMixin, View):
    login_url = "wafinstaller:login"
    audit_action = "policy.revision.mutate"

    def post(self, request, revision_id, operation):
        revision = get_object_or_404(PolicyRevision, pk=revision_id)
        if operation == "approve":
            if revision.status != PolicyRevision.Status.CANDIDATE:
                mark_audit_failure(request)
                messages.error(request, "Only candidate revisions can be approved.")
            elif (
                settings.WAFCONTROL_REQUIRE_SEPARATE_APPROVER
                and revision.created_by_id == request.user.id
            ):
                mark_audit_failure(request)
                messages.error(request, "A different user must approve this revision.")
            else:
                revision.status = PolicyRevision.Status.APPROVED
                revision.approved_by = request.user
                revision.approved_at = timezone.now()
                revision.save(update_fields=("status", "approved_by", "approved_at"))
                messages.success(request, "Immutable revision approved.")
        elif operation == "deploy":
            if revision.status != PolicyRevision.Status.APPROVED:
                mark_audit_failure(request)
                messages.error(request, "Only approved revisions can be deployed.")
            else:
                self._deploy(request, revision)
        else:
            mark_audit_failure(request)
            messages.error(request, "Unsupported revision operation.")
        return redirect("wafinstaller:policy_management")

    @staticmethod
    def _deploy(request, revision):
        bundle = PolicyBundle(
            before=revision.before_content,
            after=revision.after_content,
            active_exclusions=revision.summary.get("active_exclusions", 0),
            active_address_entries=revision.summary.get("active_address_entries", 0),
            active_applications=revision.summary.get("active_applications", 0),
            warnings=tuple(revision.summary.get("warnings", [])),
        )
        paths = get_paths()
        try:
            changed = deploy_policy_bundle(
                bundle, test_cmd=paths.test_cmd, reload_cmd=paths.reload_cmd
            )
        except PolicyDeploymentError as exc:
            revision.status = PolicyRevision.Status.FAILED
            revision.deployment_error = str(exc)[:1000]
            revision.save(update_fields=("status", "deployment_error"))
            mark_audit_failure(request)
            messages.error(request, str(exc))
            return
        with transaction.atomic():
            PolicyRevision.objects.filter(
                status=PolicyRevision.Status.DEPLOYED
            ).exclude(pk=revision.pk).update(status=PolicyRevision.Status.SUPERSEDED)
            revision.status = PolicyRevision.Status.DEPLOYED
            revision.deployed_at = timezone.now()
            revision.deployment_error = ""
            revision.save(update_fields=("status", "deployed_at", "deployment_error"))
        message = (
            "Approved revision validated and deployed."
            if changed
            else "Approved revision was already active."
        )
        messages.success(request, message)


class ManagedConfigurationCreateView(AuditedMutationMixin, LoginRequiredMixin, View):
    login_url = "wafinstaller:login"
    form_class = None
    object_label = "Configuration object"

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            instance = form.save(commit=False)
            instance.created_by = request.user
            instance.save()
            messages.success(request, f"{self.object_label} {instance} created.")
        else:
            mark_audit_failure(request)
            _report_form_errors(request, form)
        return redirect("wafinstaller:policy_management")


class ApplicationCreateView(ManagedConfigurationCreateView):
    audit_action = "policy.application.create"
    form_class = ApplicationForm
    object_label = "Application"


class WafPolicyCreateView(ManagedConfigurationCreateView):
    audit_action = "policy.policy.create"
    form_class = PolicyForm
    object_label = "Policy"


class PolicyBindingCreateView(ManagedConfigurationCreateView):
    audit_action = "policy.binding.create"
    form_class = PolicyBindingForm
    object_label = "Policy binding"
