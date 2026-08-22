import json

from django.contrib.auth import get_user_model, login
from django.contrib.auth.mixins import LoginRequiredMixin
from django.db import IntegrityError, transaction
from django.http import JsonResponse
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_protect
from django.views.decorators.debug import sensitive_post_parameters
from fido2.webauthn import AuthenticationResponse

from wafinstaller.audit import AuditedMutationMixin, mark_audit_failure, record_audit
from wafinstaller.models import AuditEntry, WebAuthnCredential
from wafinstaller.webauthn_service import (
    AUTHENTICATION_SESSION_KEY,
    REGISTRATION_SESSION_KEY,
    WebAuthnConfigurationError,
    WebAuthnStateError,
    authentication_options,
    consume_state,
    credential_data,
    get_server,
    registration_options,
    save_state,
)

User = get_user_model()
_ALLOWED_TRANSPORTS = {"ble", "hybrid", "internal", "nfc", "smart-card", "usb"}


def _json_body(request):
    if len(request.body) > 131072:
        raise ValueError("Request is too large.")
    try:
        value = json.loads(request.body or b"{}")
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid JSON request.") from exc
    if not isinstance(value, dict):
        raise ValueError("Invalid JSON request.")
    return value


def _credential_name(value):
    value = str(value or "").strip()
    if not value or len(value) > 80 or any(char in value for char in "\r\n\x00"):
        raise ValueError("Enter a name between 1 and 80 characters.")
    return value


def _pre_2fa_user(request):
    user_id = request.session.get("pre_2fa_user_id")
    if not user_id:
        return None
    try:
        return User.objects.get(pk=user_id, is_active=True, is_superuser=True)
    except User.DoesNotExist:
        return None


@method_decorator(csrf_protect, name="dispatch")
@method_decorator(sensitive_post_parameters("current_password"), name="dispatch")
class YubiKeyRegistrationOptionsView(
    AuditedMutationMixin, LoginRequiredMixin, View
):
    audit_action = "admin.webauthn.register.begin"
    login_url = "wafinstaller:login"

    def post(self, request):
        try:
            name = _credential_name(request.POST.get("name"))
            if not request.user.check_password(
                request.POST.get("current_password", "")
            ):
                raise ValueError("The current password is incorrect.")
            records = list(request.user.webauthn_credentials.all())
            if len(records) >= 10:
                raise ValueError("A maximum of 10 security keys is supported.")
            _, options, state = registration_options(request.user, records)
            save_state(
                request,
                REGISTRATION_SESSION_KEY,
                state,
                user_id=request.user.pk,
                extra={"name": name},
            )
            return JsonResponse(options)
        except (ValueError, WebAuthnConfigurationError) as exc:
            mark_audit_failure(request)
            return JsonResponse({"error": str(exc)}, status=400)


@method_decorator(csrf_protect, name="dispatch")
class YubiKeyRegistrationCompleteView(
    AuditedMutationMixin, LoginRequiredMixin, View
):
    audit_action = "admin.webauthn.register.complete"
    login_url = "wafinstaller:login"

    def post(self, request):
        try:
            body = _json_body(request)
            state, extra = consume_state(
                request,
                REGISTRATION_SESSION_KEY,
                user_id=request.user.pk,
            )
            response = body.get("credential")
            if not isinstance(response, dict):
                raise ValueError("The security key response is missing.")
            auth_data = get_server().register_complete(state, response)
            registered = auth_data.credential_data
            if registered is None:
                raise ValueError("The security key returned no credential.")
            transports = (
                response.get("response", {}).get("transports", [])
                if isinstance(response.get("response"), dict)
                else []
            )
            transports = sorted(
                {
                    str(value)
                    for value in transports
                    if str(value) in _ALLOWED_TRANSPORTS
                }
            )
            with transaction.atomic():
                WebAuthnCredential.objects.create(
                    user=request.user,
                    name=_credential_name(extra.get("name")),
                    credential_id=registered.credential_id,
                    credential_data=bytes(registered),
                    sign_count=auth_data.counter,
                    transports=transports,
                )
            return JsonResponse({"ok": True})
        except IntegrityError:
            mark_audit_failure(request)
            return JsonResponse(
                {"error": "This security key is already registered."}, status=409
            )
        except (
            KeyError,
            TypeError,
            ValueError,
            WebAuthnConfigurationError,
            WebAuthnStateError,
        ) as exc:
            mark_audit_failure(request)
            message = (
                str(exc)
                if isinstance(exc, WebAuthnStateError)
                else "Security key registration could not be verified."
            )
            return JsonResponse({"error": message}, status=400)


@method_decorator(csrf_protect, name="dispatch")
@method_decorator(sensitive_post_parameters("current_password"), name="dispatch")
class YubiKeyDeleteView(AuditedMutationMixin, LoginRequiredMixin, View):
    audit_action = "admin.webauthn.delete"
    login_url = "wafinstaller:login"

    def post(self, request, credential_id):
        credential = request.user.webauthn_credentials.filter(
            pk=credential_id
        ).first()
        if credential is None:
            mark_audit_failure(request)
            return JsonResponse({"error": "Security key not found."}, status=404)
        if not request.user.check_password(request.POST.get("current_password", "")):
            mark_audit_failure(request)
            return JsonResponse(
                {"error": "The current password is incorrect."}, status=400
            )
        credential.delete()
        return JsonResponse({"ok": True})


@method_decorator(csrf_protect, name="dispatch")
class YubiKeyAuthenticationOptionsView(View):
    def post(self, request):
        user = _pre_2fa_user(request)
        if user is None:
            return JsonResponse(
                {"error": "The authentication session has expired."}, status=401
            )
        records = list(user.webauthn_credentials.all())
        if not records:
            return JsonResponse(
                {"error": "No security key is registered for this account."},
                status=400,
            )
        try:
            _, options, state = authentication_options(records)
            save_state(
                request,
                AUTHENTICATION_SESSION_KEY,
                state,
                user_id=user.pk,
            )
            return JsonResponse(options)
        except WebAuthnConfigurationError as exc:
            return JsonResponse({"error": str(exc)}, status=400)


@method_decorator(csrf_protect, name="dispatch")
class YubiKeyAuthenticationCompleteView(View):
    def post(self, request):
        user = _pre_2fa_user(request)
        if user is None:
            return JsonResponse(
                {"error": "The authentication session has expired."}, status=401
            )
        try:
            body = _json_body(request)
            state, _ = consume_state(
                request,
                AUTHENTICATION_SESSION_KEY,
                user_id=user.pk,
            )
            with transaction.atomic():
                records = list(
                    WebAuthnCredential.objects.select_for_update().filter(user=user)
                )
                if not records:
                    raise ValueError("No security key is registered.")
                server = get_server()
                authenticated = server.authenticate_complete(
                    state,
                    credential_data(records),
                    body,
                )
                record = next(
                    (
                        item
                        for item in records
                        if bytes(item.credential_id) == authenticated.credential_id
                    ),
                    None,
                )
                if record is None:
                    raise ValueError("Unknown security key.")
                assertion = AuthenticationResponse.from_dict(body)
                received_count = assertion.response.authenticator_data.counter
                if (
                    (record.sign_count or received_count)
                    and received_count <= record.sign_count
                ):
                    raise ValueError("Security key counter did not advance.")
                record.sign_count = received_count
                record.last_used_at = timezone.now()
                record.save(update_fields=("sign_count", "last_used_at"))

            login(request, user)
            request.session.pop("pre_2fa_user_id", None)
            record_audit(
                request,
                action="auth.webauthn.verify",
                outcome=AuditEntry.Outcome.SUCCEEDED,
                target="login",
                details={"credential_id": record.pk},
            )
            return JsonResponse({"ok": True, "redirect": "/dashboard/"})
        except (
            KeyError,
            StopIteration,
            TypeError,
            ValueError,
            WebAuthnConfigurationError,
            WebAuthnStateError,
        ):
            record_audit(
                request,
                action="auth.webauthn.verify",
                outcome=AuditEntry.Outcome.FAILED,
                target="login",
            )
            return JsonResponse(
                {"error": "Security key verification failed."}, status=400
            )
