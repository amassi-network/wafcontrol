import base64
import io
import json
import os
import re
import subprocess
from collections import Counter
from pathlib import Path

import matplotlib.pyplot as plt
import pyotp
import qrcode
from celery.result import AsyncResult
from django.contrib import messages
from django.contrib.auth import get_user_model, login, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.views import LoginView
from django.contrib.auth.views import LogoutView as DjangoLogoutView
from django.db.models import Count, Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views import View
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from django.views.decorators.http import require_POST
from django.views.generic import ListView, TemplateView
from packaging.version import Version

from wafinstaller.audit import (
    AuditedMutationMixin,
    audit_mutation,
    mark_audit_failure,
)
from wafinstaller.helper.adapters import custom_after_path as _custom_after_path
from wafinstaller.helper.adapters import get_paths
from wafinstaller.helper.crs import (
    APP_KEYS,
    MODSEC_KEY_DESCRIPTIONS,
    MODSEC_KEYS,
    RULE_PATTERN,
    load_app_settings,
    save_app_settings,
)
from wafinstaller.helper.helpers import (
    get_crs_version_status,
    get_installed_crs_version,
    get_latest_crs_version,
    is_crs_update_available,
    normalize_version,
    parse_crs_version,
    run_basic_script,
    run_switch_version_script,
    run_updatecrs_script,
)
from wafinstaller.helper.utils import get_crs_full_version, get_rules_dir
from wafinstaller.security import (
    DeploymentError,
    ManagedFileError,
    deploy_managed_text,
    resolve_managed_file,
)

from .forms import AdminLogin, AdminPasswordForm, AdminProfileForm
from .models import Attack, CrsVersion, DashboardStat, TriageDecision, UserProfile
from .policy_forms import TriageDecisionForm
from .tasks import fetch_crs_versions_task, run_waf_install

User = get_user_model()


def _rule_file(filename, *, allowed_suffixes=(".conf", ".data")):
    version = get_crs_full_version()
    rule_dir = get_rules_dir(version)
    return resolve_managed_file(rule_dir, filename, allowed_suffixes=allowed_suffixes)


def _active_custom_rule_file(requested_version=None):
    active_version = normalize_version(get_crs_full_version())
    requested = normalize_version(requested_version or active_version)
    if not active_version or requested != active_version:
        raise ManagedFileError("Only the active CRS version can be modified.")
    rule_dir = get_rules_dir(active_version)
    expected_name = os.path.basename(_custom_after_path(active_version))
    return resolve_managed_file(
        rule_dir, expected_name, allowed_suffixes=(".conf",)
    ), active_version


def _deploy_text(path, content):
    paths = get_paths()
    return deploy_managed_text(
        path, content, test_cmd=paths.test_cmd, reload_cmd=paths.reload_cmd
    )


_ALLOWED_RULE_ACTIONS = {"deny", "pass", "allow", "drop", "log", "nolog"}
_ALLOWED_RULE_PHASES = {"1", "2", "3", "4", "5"}


def _safe_rule_fragment(value, field, *, max_length=1024, allow_single_quote=False):
    value = (value or "").strip()
    forbidden = '\r\n\x00"' + ("" if allow_single_quote else "'")
    if not value or len(value) > max_length or any(char in value for char in forbidden):
        raise ManagedFileError(f"Invalid {field}.")
    return value


def _build_custom_rule(request):
    rule_id = str(request.POST.get("id", ""))
    phase = str(request.POST.get("phase", ""))
    action = str(request.POST.get("action", ""))
    if not rule_id.isdigit() or len(rule_id) > 12:
        raise ManagedFileError("A numeric custom rule ID is required.")
    if phase not in _ALLOWED_RULE_PHASES or action not in _ALLOWED_RULE_ACTIONS:
        raise ManagedFileError("Invalid rule phase or action.")

    variable = _safe_rule_fragment(
        request.POST.get("variable"), "rule variable", max_length=255
    )
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_:.&!\-]*", variable):
        raise ManagedFileError("Invalid rule variable.")
    operator = _safe_rule_fragment(
        request.POST.get("operator"), "rule operator", allow_single_quote=True
    )
    actions = [f"id:{rule_id}", f"phase:{phase}", action]
    if request.POST.get("capture"):
        actions.append("capture")

    optional_single = (
        ("msg", request.POST.get("comment")),
        ("severity", request.POST.get("severity")),
        ("ver", request.POST.get("ver", "OWASP_CRS/4")),
    )
    for key, raw_value in optional_single:
        if raw_value:
            value = _safe_rule_fragment(raw_value, key, max_length=255)
            actions.append(f"{key}:'{value}'")

    for raw_tag in request.POST.get("tag", "").split(","):
        if raw_tag.strip():
            tag = _safe_rule_fragment(raw_tag, "tag", max_length=255)
            actions.append(f"tag:'{tag}'")
    for raw_transform in request.POST.get("transformations", "").split(","):
        transform = raw_transform.strip()
        if transform.startswith("t:"):
            transform = transform[2:]
        if transform:
            transform = _safe_rule_fragment(transform, "transformation", max_length=100)
            if not re.fullmatch(r"[A-Za-z0-9_\-]+", transform):
                raise ManagedFileError("Invalid transformation.")
            actions.append(f"t:{transform}")

    return rule_id, f'SecRule {variable} "{operator}" "{",".join(actions)}"\n'


# -------------------------
# Auth
# -------------------------


@method_decorator(csrf_protect, name="dispatch")
@method_decorator(sensitive_post_parameters("password"), name="dispatch")
class LoginsView(LoginView):
    template_name = "auth/login.html"
    authentication_form = AdminLogin
    redirect_authenticated_user = True

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("/dashboard/")
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        user = form.get_user()

        if not user.is_active:
            messages.error(self.request, "Your account is disabled.")
            return self.form_invalid(form)

        if not user.is_superuser:
            messages.error(self.request, "Access denied. Admin only.")
            return self.form_invalid(form)

        profile, _ = UserProfile.objects.get_or_create(user=user)
        self.request.session["pre_2fa_user_id"] = user.id

        if profile.two_factor_enabled:
            return redirect("wafinstaller:verify_2fa")

        login(self.request, user)
        return redirect("/dashboard/")

    def form_invalid(self, form):
        messages.error(self.request, "Invalid username or password.")
        return super().form_invalid(form)


class Verify2FAView(View):
    template_name = "auth/verify_2fa.html"

    def get(self, request):
        if not request.session.get("pre_2fa_user_id"):
            messages.error(request, _("Session expired. Please log in again."))
            return redirect("wafinstaller:login")
        return render(request, self.template_name)

    def post(self, request):
        user_id = request.session.get("pre_2fa_user_id")
        if not user_id:
            messages.error(request, _("Session expired. Please log in again."))
            return redirect("wafinstaller:login")

        try:
            user = User.objects.select_related("userprofile").get(id=user_id)
            secret = user.userprofile.two_factor_secret
        except (User.DoesNotExist, AttributeError):
            messages.error(request, _("Invalid authentication state."))
            return redirect("wafinstaller:login")

        code = request.POST.get("otp", "").strip()
        if not code or len(code) != 6 or not code.isdigit():
            messages.error(request, _("Please enter a valid 6-digit 2FA code."))
            return render(request, self.template_name)

        totp = pyotp.TOTP(secret)
        if not totp.verify(code):
            messages.error(request, _("Invalid 2FA code. Please try again."))
            return render(request, self.template_name)

        login(request, user)
        request.session.pop("pre_2fa_user_id", None)
        messages.success(request, _("Two-factor authentication successful."))
        return redirect("/dashboard/")


class CustomLogoutView(DjangoLogoutView):
    next_page = "wafinstaller:login"

    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)


class HomeRedirectView(View):
    def get(self, request, *args, **kwargs):
        return redirect("wafinstaller:dashboard")


# -------------------------
# WAF Install / status
# -------------------------


@login_required
@require_POST
@audit_mutation("waf.install")
def install_waf_page(request):
    """Kick off WAF installation if not installed (uses celery task)."""
    try:
        info = run_basic_script()
        waf_status = info.get("waf", {})
        if waf_status.get("exit_code") == 0:
            messages.error(request, "WAF is already installed.")
        else:
            run_waf_install.delay()
            messages.success(request, "WAF installation has been started.")
    except Exception:
        mark_audit_failure(request)
        messages.error(request, "Unable to start WAF installation.")
    return redirect("wafinstaller:dashboard")


# -------------------------
# Dashboard
# -------------------------


class DashboardView(AuditedMutationMixin, LoginRequiredMixin, TemplateView):
    audit_action = "crs.update"
    template_name = "dashboard/panel/panel.html"
    login_url = "wafinstaller:login"

    def post(self, request):
        """Manual CRS update from UI (sync)."""
        exit_code, log = run_updatecrs_script()
        if exit_code != 0:
            mark_audit_failure(request)
        return JsonResponse(
            {"status": "done", "exit_code": exit_code, "log": log},
            status=200 if exit_code == 0 else 409,
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)

        # server/waf state
        service_data = run_basic_script()
        waf_data = service_data.get("waf", {"exit_code": 1, "version": ""})

        installed_crs = get_installed_crs_version()
        latest_crs = get_latest_crs_version()
        crs_version_status = get_crs_version_status(installed_crs, latest_crs)

        context.update(
            {
                "nginx": service_data.get("nginx", {"exit_code": 1, "version": ""}),
                "apache": service_data.get("apache", {"exit_code": 1, "version": ""}),
                "waf": waf_data,
                "installed_crs": installed_crs,
                "latest_crs": latest_crs,
                "update_available": is_crs_update_available(installed_crs, latest_crs),
                "crs_version_status": crs_version_status,
                "active_server": service_data.get("server", "none"),
            }
        )

        # system stats
        latest_stats = DashboardStat.objects.order_by("-fetched_at").first()
        context.update(
            {
                "cpu_usage": latest_stats.cpu_usage if latest_stats else "0",
                "cpu_load": latest_stats.cpu_load if latest_stats else "0",
                "ram_usage": latest_stats.ram_usage if latest_stats else "0",
                "disk_usage": latest_stats.disk_usage if latest_stats else "0",
                "storage_free": latest_stats.storage_free if latest_stats else "0",
                "total_processes": latest_stats.total_processes
                if latest_stats
                else "0",
                "total_threads": latest_stats.total_threads if latest_stats else "0",
                "total_handles": latest_stats.total_handles if latest_stats else "0",
            }
        )

        # attacks pie chart (countries)
        country_counts = Counter(Attack.objects.values_list("country", flat=True))
        if country_counts:
            fig, ax = plt.subplots()
            ax.pie(
                country_counts.values(),
                labels=country_counts.keys(),
                autopct="%1.1f%%",
                startangle=140,
            )
            ax.axis("equal")
            buf = io.BytesIO()
            plt.savefig(buf, format="png", bbox_inches="tight")
            buf.seek(0)
            context["waf_chart_base64"] = base64.b64encode(buf.read()).decode("utf-8")
            buf.close()
        else:
            context["waf_chart_base64"] = ""

        context["recent_attacks"] = Attack.objects.order_by("-timestamp")[:5]
        return context


# -------------------------
# Attacks list / critical / top
# -------------------------


class WafAttacksView(LoginRequiredMixin, ListView):
    model = Attack
    template_name = "dashboard/panel/attacks.html"
    context_object_name = "attacks"
    paginate_by = 30
    login_url = "wafinstaller:login"

    def get_queryset(self):
        qs = Attack.objects.select_related("triage").all().order_by("-timestamp")
        ip = self.request.GET.get("ip")
        rule_id = self.request.GET.get("rule_id")
        status = self.request.GET.get("status")
        start_date = self.request.GET.get("start_date")
        end_date = self.request.GET.get("end_date")
        host = self.request.GET.get("host")
        classification = self.request.GET.get("classification")

        if ip:
            qs = qs.filter(ip__icontains=ip)
        if rule_id:
            qs = qs.filter(rule_id__icontains=rule_id)
        if status:
            qs = qs.filter(status=status)
        if start_date:
            qs = qs.filter(timestamp__date__gte=start_date)
        if end_date:
            qs = qs.filter(timestamp__date__lte=end_date)
        if host:
            qs = qs.filter(host__icontains=host)
        if classification:
            qs = qs.filter(triage__classification=classification)

        return qs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["total_attacks"] = Attack.objects.count()
        context["filtered_count"] = self.get_queryset().count()

        repeated_ips = list(
            Attack.objects.values("ip")
            .annotate(count=Count("ip"))
            .filter(count__gt=3)
            .values_list("ip", flat=True)
        )
        context["repeated_attackers"] = repeated_ips

        context["triage_choices"] = TriageDecision.Classification.choices
        context["triage_form"] = TriageDecisionForm()
        for attack in context["attacks"]:
            if attack.severity >= 3:  # High / Critical
                attack.row_class = "table-danger"
            elif attack.severity == 2:  # Medium
                attack.row_class = "table-warning"
            elif attack.ip in repeated_ips:
                attack.row_class = "table-warning"  #
            else:  # Low / Info
                attack.row_class = "table-light"  #

        return context


class TopAttackersView(LoginRequiredMixin, ListView):
    template_name = "dashboard/panel/top_attackers.html"
    context_object_name = "attackers"
    paginate_by = 20
    login_url = "wafinstaller:login"

    def get_queryset(self):
        qs = (
            Attack.objects.values("ip", "country", "flag")
            .annotate(total=Count("id"))
            .order_by("-total")
        )
        ip = self.request.GET.get("ip")
        country = self.request.GET.get("country")
        if ip:
            qs = qs.filter(ip__icontains=ip)
        if country:
            qs = qs.filter(country__icontains=country)
        return qs


class CriticalWafAttacksView(LoginRequiredMixin, ListView):
    model = Attack
    template_name = "dashboard/panel/critical_attacks.html"
    context_object_name = "attacks"
    paginate_by = 20
    ordering = ["-timestamp"]
    login_url = "wafinstaller:login"

    # Rule families considered critical
    CRITICAL_FAMILIES = ("942", "930", "932", "941", "931", "933")
    NOISE_RULES = ("980170",)  # Rules to ignore

    def get_queryset(self):
        # Build base query for critical rule families
        q = Q()
        for fam in self.CRITICAL_FAMILIES:
            q |= Q(rule_id__startswith=fam)
        for rid in self.NOISE_RULES:
            q &= ~Q(rule_id=rid)

        attacks = Attack.objects.filter(q).order_by("-timestamp")

        # Apply filters from GET parameters
        ip = self.request.GET.get("ip")
        rule_id = self.request.GET.get("rule_id")
        status = self.request.GET.get("status")
        start_date = self.request.GET.get("start_date")
        end_date = self.request.GET.get("end_date")
        host = self.request.GET.get("host")

        if ip:
            attacks = attacks.filter(ip__icontains=ip)
        if rule_id:
            attacks = attacks.filter(rule_id__icontains=rule_id)
        if status:
            attacks = attacks.filter(status=status)
        if start_date:
            attacks = attacks.filter(timestamp__date__gte=start_date)
        if end_date:
            attacks = attacks.filter(timestamp__date__lte=end_date)
        if host:
            attacks = attacks.filter(host__icontains=host)

        return attacks

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["total_attacks"] = Attack.objects.count()
        context["filtered_count"] = self.get_queryset().count()
        return context

        # -------------------------


# CRS update (sync)
# -------------------------


class CrsUpdateSyncView(AuditedMutationMixin, LoginRequiredMixin, View):
    audit_action = "crs.update"
    login_url = "wafinstaller:login"

    def post(self, request):
        exit_code, log = run_updatecrs_script()
        if exit_code != 0:
            mark_audit_failure(request)
        return JsonResponse(
            {"status": "done", "exit_code": exit_code, "log": log},
            status=200 if exit_code == 0 else 409,
        )


@method_decorator(login_required, name="dispatch")
class GetTaskStatusView(LoginRequiredMixin, View):
    login_url = "wafinstaller:login"

    def get(self, request, task_id, *args, **kwargs):
        task_result = AsyncResult(task_id)
        if task_result.state == "PROGRESS":
            return JsonResponse(
                {"status": "progress", "line": task_result.info.get("line")}
            )
        elif task_result.state == "SUCCESS":
            return JsonResponse({"status": "done", "result": task_result.result})
        elif task_result.state == "FAILURE":
            return JsonResponse({"status": "error", "error": str(task_result.result)})
        else:
            return JsonResponse({"status": task_result.state})


# -------------------------
# CRS files/rules browsing
# -------------------------


class CRSRuleListView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/panel/crs_rules.html"
    login_url = "wafinstaller:login"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        version = get_crs_full_version()
        rule_dir = get_rules_dir(version)
        files = []
        try:
            if rule_dir and os.path.isdir(rule_dir):
                for filename in sorted(os.listdir(rule_dir)):
                    if filename.endswith((".conf", ".data")):
                        files.append(filename)
            else:
                files.append(f"[Directory not found]: {rule_dir}")
        except Exception as e:
            files.append(f"[Error]: {str(e)}")

        context.update({"crs_version": version, "rule_files": files})
        return context


class ReadCRSRuleView(LoginRequiredMixin, View):
    login_url = "wafinstaller:login"

    def get(self, request, filename):
        try:
            file_path = _rule_file(filename)
            return JsonResponse(
                {"success": True, "content": file_path.read_text(encoding="utf-8")}
            )
        except ManagedFileError as exc:
            return JsonResponse({"success": False, "error": str(exc)}, status=400)
        except (OSError, UnicodeError):
            return JsonResponse(
                {"success": False, "error": "Unable to read the managed file."},
                status=500,
            )


class SaveCRSRuleView(AuditedMutationMixin, LoginRequiredMixin, View):
    audit_action = "crs.rule.save"
    login_url = "wafinstaller:login"

    def post(self, request, filename):
        try:
            data = json.loads(request.body)
            content = data.get("content")
            if not isinstance(content, str):
                raise ManagedFileError("Rule content must be a string.")
            file_path = _rule_file(filename)
            changed = _deploy_text(file_path, content)
            return JsonResponse({"success": True, "changed": changed})
        except (json.JSONDecodeError, ManagedFileError) as exc:
            return JsonResponse({"success": False, "error": str(exc)}, status=400)
        except DeploymentError as exc:
            return JsonResponse({"success": False, "error": str(exc)}, status=409)
        except (OSError, UnicodeError):
            return JsonResponse(
                {"success": False, "error": "Unable to update the managed file."},
                status=500,
            )


class CRSCategoriesView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/panel/crs_categories.html"
    login_url = "wafinstaller:login"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        version = get_crs_full_version()
        rule_dir = get_rules_dir(version)
        rule_files = []
        if rule_dir and os.path.isdir(rule_dir):
            rule_files = [
                f for f in sorted(os.listdir(rule_dir)) if f.endswith(".conf")
            ]
        context.update({"crs_version": version, "rule_files": rule_files})
        return context


class CRSRuleListByFileView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/panel/crs_rules_by_file.html"
    login_url = "wafinstaller:login"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        version = get_crs_full_version()
        filename = kwargs.get("filename")
        rules = []
        try:
            file_path = _rule_file(filename, allowed_suffixes=(".conf",))
            lines = file_path.read_text(encoding="utf-8").splitlines(keepends=True)
            i = 0
            while i < len(lines):
                line = lines[i]
                raw_lines = [line]
                start_index = i
                if re.search(r"(SecRule|SecAction)", line):
                    while line.rstrip().endswith("\\") and i + 1 < len(lines):
                        i += 1
                        line = lines[i]
                        raw_lines.append(line)
                    full_rule = "".join(raw_lines)
                    rid = re.search(r'id\s*:\s*"?(\d+)"?', full_rule)
                    msg = re.search(r"msg\s*:\s*'(.*?)'", full_rule)
                    rules.append(
                        {
                            "id": rid.group(1) if rid else "unknown",
                            "msg": msg.group(1) if msg else "",
                            "enabled": not all(
                                item.lstrip().startswith("#") for item in raw_lines
                            ),
                            "filename": filename,
                            "line_number": start_index + 1,
                            "raw": "".join(raw_lines).strip(),
                        }
                    )
                i += 1
        except ManagedFileError as exc:
            messages.error(self.request, str(exc))
        except (OSError, UnicodeError):
            messages.error(self.request, "Unable to read the managed rule file.")

        context.update({"rules": rules, "filename": filename, "crs_version": version})
        return context


class ToggleCRSRuleView(AuditedMutationMixin, LoginRequiredMixin, View):
    audit_action = "crs.rule.toggle"
    login_url = "wafinstaller:login"

    def post(self, request):
        try:
            data = json.loads(request.body)
            rule_id = str(data.get("rule_id", ""))
            filename = data.get("filename")
            enable = data.get("enable") is True
            if not rule_id.isdigit() or not isinstance(filename, str):
                raise ManagedFileError("A numeric rule ID and filename are required.")

            file_path = _rule_file(filename, allowed_suffixes=(".conf",))
            lines = file_path.read_text(encoding="utf-8").splitlines(keepends=True)
            new_lines, found, index = [], False, 0
            while index < len(lines):
                line = lines[index]
                if re.search(r"^\s*(#\s*)?(SecRule|SecAction)", line):
                    rule_lines, rule_text = [line], line
                    index += 1
                    while index < len(lines) and (
                        lines[index].rstrip().endswith("\\")
                        or not re.search(
                            r"^\s*(#\s*)?(SecRule|SecAction)", lines[index]
                        )
                    ):
                        rule_lines.append(lines[index])
                        rule_text += lines[index]
                        index += 1
                    if re.search(
                        r'id\s*:\s*"?' + re.escape(rule_id) + r'"?', rule_text
                    ):
                        found = True
                        if enable:
                            new_lines.extend(
                                [re.sub(r"^\s*#\s*", "", item) for item in rule_lines]
                            )
                        else:
                            new_lines.extend(
                                [
                                    "# " + item
                                    if not item.strip().startswith("#")
                                    else item
                                    for item in rule_lines
                                ]
                            )
                    else:
                        new_lines.extend(rule_lines)
                else:
                    new_lines.append(line)
                    index += 1

            if not found:
                return JsonResponse(
                    {"success": False, "error": f"Rule ID {rule_id} not found."},
                    status=404,
                )
            changed = _deploy_text(file_path, "".join(new_lines))
            return JsonResponse(
                {"success": True, "enabled": enable, "changed": changed}
            )
        except (json.JSONDecodeError, ManagedFileError) as exc:
            return JsonResponse({"success": False, "error": str(exc)}, status=400)
        except DeploymentError as exc:
            return JsonResponse({"success": False, "error": str(exc)}, status=409)
        except (OSError, UnicodeError):
            return JsonResponse(
                {"success": False, "error": "Unable to update the managed rule."},
                status=500,
            )


class UpdateSingleCRSRuleView(AuditedMutationMixin, LoginRequiredMixin, View):
    audit_action = "crs.rule.update"
    login_url = "wafinstaller:login"

    def post(self, request, filename):
        try:
            body = json.loads(request.body)
            new_rule = body.get("content", "")
            if not isinstance(new_rule, str):
                raise ManagedFileError("Rule content must be a string.")
            new_rule = new_rule.strip()
            rule_id_match = re.search(
                r"\bid\s*:\s*[\"']?(\d+)[\"']?", new_rule, re.IGNORECASE
            )
            if not rule_id_match:
                raise ManagedFileError("Rule ID not found in new content.")
            rule_id = rule_id_match.group(1)
            file_path = _rule_file(filename, allowed_suffixes=(".conf",))
            lines = file_path.read_text(encoding="utf-8").splitlines(keepends=True)

            new_lines, index, found = [], 0, False
            while index < len(lines):
                line = lines[index]
                if line.lstrip().startswith(("SecRule", "SecAction")):
                    rule_lines = [line]
                    index += 1
                    while index < len(lines):
                        current_line = lines[index]
                        rule_lines.append(current_line)
                        index += 1
                        if (
                            not current_line.lstrip().startswith('"')
                            and not current_line.strip().startswith("#")
                            and current_line.strip()
                        ):
                            break
                    full_rule = "".join(rule_lines)
                    current_id = re.search(
                        r"\bid\s*:\s*[\"']?(\d+)[\"']?",
                        full_rule,
                        re.IGNORECASE,
                    )
                    if current_id and current_id.group(1) == rule_id:
                        new_lines.append(new_rule + "\n")
                        found = True
                    else:
                        new_lines.extend(rule_lines)
                else:
                    new_lines.append(line)
                    index += 1

            if not found:
                return JsonResponse(
                    {
                        "success": False,
                        "error": f"Rule ID {rule_id} not found in file.",
                    },
                    status=404,
                )
            changed = _deploy_text(file_path, "".join(new_lines))
            return JsonResponse({"success": True, "changed": changed})
        except (json.JSONDecodeError, ManagedFileError) as exc:
            return JsonResponse({"success": False, "error": str(exc)}, status=400)
        except DeploymentError as exc:
            return JsonResponse({"success": False, "error": str(exc)}, status=409)
        except (OSError, UnicodeError):
            return JsonResponse(
                {"success": False, "error": "Unable to update the managed rule."},
                status=500,
            )


# -------------------------
# Server network/traffic
# -------------------------


class ServerTrafficAnalysisView(LoginRequiredMixin, TemplateView):
    template_name = "dashboard/panel/server_traffic.html"
    login_url = "wafinstaller:login"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        try:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            script_path = os.path.join(base_dir, "scripts", "netstat.sh")
            output = subprocess.check_output([script_path], text=True)
        except Exception as e:
            context["error"] = str(e)
            return context

        sections = output.split("---")
        context["connection_count"] = sections[1].strip() if len(sections) > 1 else "0"
        context["top_ips"] = self._parse_ip_counts(
            sections[2] if len(sections) > 2 else ""
        )
        context["syn_recv_ips"] = self._parse_ip_counts(
            sections[3] if len(sections) > 3 else ""
        )
        context["states"] = self._parse_states(sections[4] if len(sections) > 4 else "")
        return context

    def _parse_ip_counts(self, raw: str):
        lines = raw.strip().splitlines()
        return [
            {"ip": line.split()[-1], "count": int(line.split()[0])}
            for line in lines
            if line.strip()
        ]

    def _parse_states(self, raw: str):
        lines = raw.strip().splitlines()
        return [
            {"state": line.split()[-1], "count": int(line.split()[0])}
            for line in lines
            if line.strip()
        ]


# -------------------------
# CRS versions page / switch
# -------------------------


class CrsVersionListView(LoginRequiredMixin, View):
    login_url = "wafinstaller:login"

    def get(self, request):
        versions = list(CrsVersion.objects.all())
        versions.sort(
            key=lambda item: parse_crs_version(item.tag) or Version("0"),
            reverse=True,
        )
        installed_version = get_installed_crs_version()
        latest_version = get_latest_crs_version()

        for v in versions:
            v.normalized_tag = normalize_version(v.tag)

        return render(
            request,
            "dashboard/panel/crs_versions.html",
            {
                "versions": versions,
                "fetched_at": max(
                    (version.fetched_at for version in versions), default="N/A"
                ),
                "installed_version": installed_version,
                "latest_version": latest_version,
                "version_status": get_crs_version_status(
                    installed_version, latest_version
                ),
            },
        )


class CrsSwitchVersionView(AuditedMutationMixin, LoginRequiredMixin, View):
    audit_action = "crs.version.switch"
    login_url = "wafinstaller:login"

    def post(self, request):
        version = normalize_version(request.POST.get("version"))
        known_versions = {
            normalize_version(tag)
            for tag in CrsVersion.objects.values_list("tag", flat=True)
        }
        if not version or version not in known_versions:
            mark_audit_failure(request)
            messages.error(request, "Select a valid version from the CRS catalog.")
            return redirect("wafinstaller:crs_version")

        exit_code, _stderr = run_switch_version_script(version)
        if exit_code == 0:
            messages.success(request, f"CRS successfully switched to {version}.")
        else:
            mark_audit_failure(request)
            messages.error(request, "CRS switch failed; review the server logs.")
        return redirect("wafinstaller:crs_version")


# -------------------------
# ModSecurity settings
# -------------------------


class ModSecuritySettingsView(AuditedMutationMixin, LoginRequiredMixin, View):
    audit_action = "modsecurity.settings.update"
    template_name = "dashboard/panel/waf_settings.html"
    login_url = "wafinstaller:login"

    def get(self, request):
        paths = get_paths()
        settings_map = {}
        try:
            content = Path(paths.modsec_conf).read_text(encoding="utf-8")
            for key in MODSEC_KEYS:
                match = re.search(
                    rf"^\s*{re.escape(key)}\s+(.+)", content, re.MULTILINE
                )
                settings_map[key] = {
                    "value": match.group(1).strip() if match else "",
                    "description": MODSEC_KEY_DESCRIPTIONS.get(key, ""),
                }
        except (OSError, UnicodeError):
            messages.error(request, "Unable to read the ModSecurity configuration.")
        return render(request, self.template_name, {"settings": settings_map})

    def post(self, request):
        paths = get_paths()
        try:
            config_path = Path(paths.modsec_conf).resolve(strict=True)
            lines = config_path.read_text(encoding="utf-8").splitlines(keepends=True)
            values = {}
            for key in MODSEC_KEYS:
                value = request.POST.get(key, "").strip()
                if (
                    not value
                    or len(value) > 1024
                    or any(c in value for c in "\r\n\x00")
                ):
                    raise ManagedFileError(f"Invalid value for {key}.")
                values[key] = value

            updated_lines = []
            for line in lines:
                replacement = None
                for key, value in values.items():
                    if line.strip().startswith(key):
                        replacement = f"{key} {value}\n"
                        break
                updated_lines.append(replacement if replacement is not None else line)

            changed = deploy_managed_text(
                config_path,
                "".join(updated_lines),
                test_cmd=paths.test_cmd,
                reload_cmd=paths.reload_cmd,
            )
            messages.success(
                request,
                "ModSecurity settings updated and reloaded."
                if changed
                else "No ModSecurity configuration change was required.",
            )
        except ManagedFileError as exc:
            mark_audit_failure(request)
            messages.error(request, str(exc))
        except DeploymentError as exc:
            mark_audit_failure(request)
            messages.error(request, str(exc))
        except (OSError, UnicodeError):
            mark_audit_failure(request)
            messages.error(request, "Unable to update the ModSecurity configuration.")
        return redirect("wafinstaller:crs_settings")


# -------------------------
# AFTER-CRS custom rules
# -------------------------


class CustomRulesView(LoginRequiredMixin, View):
    login_url = "wafinstaller:login"

    def get(self, request):
        actions = sorted(_ALLOWED_RULE_ACTIONS)
        rules = []
        version = None
        try:
            path, version = _active_custom_rule_file(request.GET.get("version"))
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line.startswith("SecRule"):
                    continue
                match = RULE_PATTERN.match(line)
                if not match:
                    continue
                rule = {
                    "variable": match.group(1),
                    "operator": match.group(2),
                    "id": match.group(3),
                    "phase": match.group(4),
                    "action": match.group(5),
                    "comment": match.group(6) if match.lastindex >= 6 else "",
                }
                if "severity:" in line:
                    rule["severity"] = self._extract_value(line, "severity")
                if "tag:" in line:
                    rule["tag"] = ",".join(self._extract_all_values(line, "tag"))
                if "t:" in line:
                    rule["transformations"] = ",".join(
                        self._extract_all_values(line, "t")
                    )
                if "ver:" in line:
                    rule["ver"] = self._extract_value(line, "ver")
                if "capture" in line:
                    rule["capture"] = True
                rules.append(rule)
        except ManagedFileError as exc:
            messages.error(request, str(exc))
        except (OSError, UnicodeError):
            messages.error(request, "Unable to read the managed custom-rule file.")

        return render(
            request,
            "dashboard/panel/custom_rules_list.html",
            {"rules": rules, "version": version, "actions": actions},
        )

    def _extract_value(self, text, key):
        match = re.search(rf"{key}:(?:'([^']+)'|([^,\"]+))", text)
        return (match.group(1) or match.group(2)).strip() if match else ""

    def _extract_all_values(self, text, key):
        matches = re.findall(rf"{key}:(?:'([^']+)'|([^,\"]+))", text)
        return [(match[0] or match[1]).strip() for match in matches]


class AddCustomRuleView(AuditedMutationMixin, LoginRequiredMixin, View):
    audit_action = "custom_rule.add"
    login_url = "wafinstaller:login"

    def get(self, request):
        version = normalize_version(get_crs_full_version())
        return render(
            request, "dashboard/panel/custom_rule_add.html", {"version": version}
        )

    def post(self, request):
        version = normalize_version(get_crs_full_version())
        try:
            path, version = _active_custom_rule_file(request.POST.get("version"))
            rule_id, rule_line = _build_custom_rule(request)
            current = path.read_text(encoding="utf-8")
            if re.search(rf"\bid\s*:\s*[\"']?{re.escape(rule_id)}\b", current):
                raise ManagedFileError(f"Rule ID {rule_id} already exists.")
            _deploy_text(path, current + rule_line)
            messages.success(request, "Custom rule added and web server reloaded.")
        except (ManagedFileError, DeploymentError) as exc:
            mark_audit_failure(request)
            messages.error(request, str(exc))
        except (OSError, UnicodeError):
            mark_audit_failure(request)
            messages.error(request, "Unable to add the custom rule.")
        return redirect(
            reverse("wafinstaller:custom_rules") + f"?version={version or ''}"
        )


class EditCustomRuleView(AuditedMutationMixin, LoginRequiredMixin, View):
    audit_action = "custom_rule.edit"
    login_url = "wafinstaller:login"

    def post(self, request, rule_id):
        version = normalize_version(get_crs_full_version())
        try:
            if not str(rule_id).isdigit():
                raise ManagedFileError("A numeric rule ID is required.")
            path, version = _active_custom_rule_file(request.POST.get("version"))
            new_id, new_rule = _build_custom_rule(request)
            lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
            updated_lines, found = [], False
            for line in lines:
                current = re.search(r"\bid\s*:\s*[\"']?(\d+)", line)
                if current and current.group(1) == str(rule_id):
                    updated_lines.append(new_rule)
                    found = True
                else:
                    updated_lines.append(line)
            if not found:
                raise ManagedFileError(f"Rule ID {rule_id} was not found.")
            if new_id != str(rule_id) and re.search(
                rf"\bid\s*:\s*[\"']?{re.escape(new_id)}\b",
                "".join(lines),
            ):
                raise ManagedFileError(f"Rule ID {new_id} already exists.")
            _deploy_text(path, "".join(updated_lines))
            messages.success(request, f"Rule {rule_id} updated and reloaded.")
        except (ManagedFileError, DeploymentError) as exc:
            mark_audit_failure(request)
            messages.error(request, str(exc))
        except (OSError, UnicodeError):
            mark_audit_failure(request)
            messages.error(request, "Unable to update the custom rule.")
        return redirect(
            reverse("wafinstaller:custom_rules") + f"?version={version or ''}"
        )


class DeleteCustomRuleView(AuditedMutationMixin, LoginRequiredMixin, View):
    audit_action = "custom_rule.delete"
    login_url = "wafinstaller:login"

    def post(self, request, rule_id):
        version = normalize_version(get_crs_full_version())
        try:
            path, version = _active_custom_rule_file(request.POST.get("version"))
            lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
            updated_lines, found = [], False
            for line in lines:
                current = re.search(r"\bid\s*:\s*[\"']?(\d+)", line)
                if current and current.group(1) == str(rule_id):
                    found = True
                    continue
                updated_lines.append(line)
            if not found:
                raise ManagedFileError(f"Rule ID {rule_id} was not found.")
            _deploy_text(path, "".join(updated_lines))
            messages.success(request, f"Rule {rule_id} deleted and reloaded.")
        except (ManagedFileError, DeploymentError) as exc:
            mark_audit_failure(request)
            messages.error(request, str(exc))
        except (OSError, UnicodeError):
            mark_audit_failure(request)
            messages.error(request, "Unable to delete the custom rule.")
        return redirect(
            reverse("wafinstaller:custom_rules") + f"?version={version or ''}"
        )


# -------------------------
# App settings (WafControl)
# -------------------------


class AppSettingsView(AuditedMutationMixin, LoginRequiredMixin, View):
    audit_action = "application.settings.update"
    template_name = "dashboard/panel/app_settings.html"
    login_url = "wafinstaller:login"

    def get(self, request):
        settings_map = {}
        app_config = load_app_settings()
        for key, meta in APP_KEYS.items():
            settings_map[key] = {
                "value": app_config.get(key, meta["default"]),
                "description": meta["description"],
            }
        return render(request, self.template_name, {"settings": settings_map})

    def post(self, request):
        try:
            retention = request.POST.get("AttackRetentionDays", "").strip()
            if not retention.isdigit() or not 1 <= int(retention) <= 3650:
                raise ValueError("Attack retention must be between 1 and 3650 days.")
            save_app_settings({"AttackRetentionDays": retention})
            messages.success(request, "Application settings saved successfully.")
        except (AttributeError, ValueError) as exc:
            mark_audit_failure(request)
            messages.error(request, str(exc))
        except Exception:
            mark_audit_failure(request)
            messages.error(request, "Unable to save application settings.")
        return redirect("wafinstaller:app_settings")


# -------------------------
# Admin profile (2FA)
# -------------------------


class AdminProfileView(AuditedMutationMixin, LoginRequiredMixin, View):
    audit_action = "admin.profile.update"
    login_url = "wafinstaller:login"

    def get(self, request):
        profile_form = AdminProfileForm(instance=request.user)
        password_form = AdminPasswordForm(user=request.user)

        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        qr_code = None

        if not profile.two_factor_enabled and profile.two_factor_secret:
            totp = pyotp.TOTP(profile.two_factor_secret)
            uri = totp.provisioning_uri(
                name=request.user.email, issuer_name="OWASP WAFControl"
            )
            qr = qrcode.make(uri)
            buffer = io.BytesIO()
            qr.save(buffer, format="PNG")
            qr_code = base64.b64encode(buffer.getvalue()).decode()

        active_tab = request.GET.get("tab", "personal-information")

        return render(
            request,
            "dashboard/panel/admin_profile.html",
            {
                "profile_form": profile_form,
                "password_form": password_form,
                "qr_code": qr_code,
                "secret": profile.two_factor_secret,
                "active_tab": active_tab,
            },
        )

    def post(self, request):
        user = request.user
        profile, _ = UserProfile.objects.get_or_create(user=user)

        if "update_profile" in request.POST:
            profile_form = AdminProfileForm(request.POST, instance=user)
            if profile_form.is_valid():
                profile_form.save()
                messages.success(request, "Profile updated successfully.")
                return redirect("/dashboard/profile/?tab=personal-information")
            mark_audit_failure(request)
            messages.error(request, "Profile validation failed.")
            return redirect("/dashboard/profile/?tab=personal-information")

        elif "change_password" in request.POST:
            password_form = AdminPasswordForm(user=user, data=request.POST)
            if password_form.is_valid():
                user = password_form.save()
                update_session_auth_hash(request, user)
                messages.success(request, "Password changed successfully.")
                return redirect("/dashboard/profile/?tab=change-password")
            else:
                mark_audit_failure(request)
                messages.error(request, "Password change failed.")
                return redirect("/dashboard/profile/?tab=change-password")

        elif "start_2fa" in request.POST:
            secret = pyotp.random_base32()
            profile.two_factor_secret = secret
            profile.save()
            return redirect("/dashboard/profile/?tab=two-factor")

        elif "enable_2fa" in request.POST:
            otp = request.POST.get("otp")
            totp = pyotp.TOTP(profile.two_factor_secret)
            if totp.verify(otp):
                profile.two_factor_enabled = True
                profile.save()
                messages.success(request, "Two-Factor Authentication enabled.")
            else:
                mark_audit_failure(request)
                messages.error(request, "Invalid verification code.")
            return redirect("/dashboard/profile/?tab=two-factor")

        elif "disable_2fa" in request.POST:
            otp = request.POST.get("otp")
            totp = pyotp.TOTP(profile.two_factor_secret)
            if totp.verify(otp):
                profile.two_factor_enabled = False
                profile.two_factor_secret = ""
                profile.save()
                messages.success(request, "Two-Factor Authentication disabled.")
            else:
                mark_audit_failure(request)
                messages.error(request, "Invalid 2FA code. Deactivation failed.")
            return redirect("/dashboard/profile/?tab=two-factor")

        mark_audit_failure(request)
        messages.error(request, "Unknown profile operation.")
        return redirect("/dashboard/profile/")


# -------------------------
# Force-fetch CRS versions
# -------------------------


class ForceFetchCrsVersionsView(AuditedMutationMixin, LoginRequiredMixin, View):
    audit_action = "crs.catalog.refresh"
    login_url = "wafinstaller:login"

    def post(self, request):
        try:
            versions = fetch_crs_versions_task()
            if not versions:
                raise RuntimeError("No stable release was returned.")
            messages.success(request, "Successfully fetched the latest CRS versions.")
        except Exception:
            mark_audit_failure(request)
            messages.error(request, "Unable to refresh the CRS release catalog.")
        return redirect("wafinstaller:crs_version")


class EventTriageView(AuditedMutationMixin, LoginRequiredMixin, View):
    login_url = "wafinstaller:login"
    audit_action = "event.triage"

    def post(self, request, attack_id):
        attack = get_object_or_404(Attack, pk=attack_id)
        current = TriageDecision.objects.filter(attack=attack).first()
        form = TriageDecisionForm(request.POST, instance=current)
        if form.is_valid():
            decision = form.save(commit=False)
            decision.attack = attack
            decision.decided_by = request.user
            decision.save()
            messages.success(
                request,
                f"Event #{attack.pk} classified as {decision.get_classification_display()}.",
            )
        else:
            mark_audit_failure(request)
            for errors in form.errors.values():
                for error in errors:
                    messages.error(request, error)
        return redirect("wafinstaller:waf_attacks")
