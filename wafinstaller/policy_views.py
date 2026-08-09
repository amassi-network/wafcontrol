from typing import ClassVar
from urllib.parse import urlsplit

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect
from django.views import View
from django.views.generic import TemplateView

from wafinstaller.audit import AuditedMutationMixin, mark_audit_failure
from wafinstaller.helper.adapters import get_paths
from wafinstaller.models import AddressEntry, AddressList, Attack, RuleExclusion
from wafinstaller.policy import (
    PolicyDeploymentError,
    deploy_policy_bundle,
    include_directives,
    include_status,
    policy_diff,
    render_policy,
)
from wafinstaller.policy_forms import (
    AddressEntryForm,
    AddressListForm,
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
            "kind": RuleExclusion.Kind.REMOVE_RULE,
            "rule_id": rule_id,
            "host": host,
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
        return events.count()

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        bundle = render_policy()
        initial, source_attack = self._exclusion_initial()
        exclusions = list(RuleExclusion.objects.all())
        for exclusion in exclusions:
            exclusion.impact_count = self._impact_count(exclusion)
        context.update(
            {
                "address_lists": AddressList.objects.prefetch_related("entries").all(),
                "exclusions": exclusions,
                "address_list_form": AddressListForm(),
                "address_entry_form": AddressEntryForm(),
                "exclusion_form": RuleExclusionForm(initial=initial),
                "source_attack": source_attack,
                "policy_bundle": bundle,
                "policy_diff": policy_diff(bundle),
                "include_status": include_status(),
                "include_directives": include_directives(),
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
    }

    def post(self, request, object_type, object_id, operation):
        model = self.models.get(object_type)
        if model is None or operation not in {"toggle", "approve", "delete"}:
            mark_audit_failure(request)
            messages.error(request, "Unsupported policy operation.")
            return redirect("wafinstaller:policy_management")

        instance = get_object_or_404(model, pk=object_id)
        if operation == "delete":
            label = str(instance)
            instance.delete()
            messages.success(request, f"{label} deleted.")
        elif operation == "approve" and isinstance(instance, RuleExclusion):
            instance.status = (
                RuleExclusion.Status.DRAFT
                if instance.status == RuleExclusion.Status.APPROVED
                else RuleExclusion.Status.APPROVED
            )
            instance.save(update_fields=("status", "updated_at"))
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
        bundle = render_policy()
        paths = get_paths()
        try:
            changed = deploy_policy_bundle(
                bundle,
                test_cmd=paths.test_cmd,
                reload_cmd=paths.reload_cmd,
            )
            messages.success(
                request,
                "Policy validated and deployed."
                if changed
                else "The generated policy is already active.",
            )
        except PolicyDeploymentError as exc:
            mark_audit_failure(request)
            messages.error(request, str(exc))
        return redirect("wafinstaller:policy_management")
