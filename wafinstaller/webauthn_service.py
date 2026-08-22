import time
from collections.abc import Iterable

from django.conf import settings
from fido2.server import Fido2Server
from fido2.webauthn import (
    AttestationConveyancePreference,
    AttestedCredentialData,
    AuthenticatorAttachment,
    PublicKeyCredentialRpEntity,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)


class WebAuthnConfigurationError(RuntimeError):
    pass


class WebAuthnStateError(ValueError):
    pass


REGISTRATION_SESSION_KEY = "webauthn_registration"
AUTHENTICATION_SESSION_KEY = "webauthn_authentication"


def get_server():
    rp_id = settings.WEBAUTHN_RP_ID.strip()
    origins = frozenset(settings.WEBAUTHN_ALLOWED_ORIGINS)
    if not rp_id or not origins:
        raise WebAuthnConfigurationError(
            "WebAuthn RP ID and allowed origins must be configured."
        )
    rp = PublicKeyCredentialRpEntity(id=rp_id, name=settings.WEBAUTHN_RP_NAME)
    return Fido2Server(
        rp,
        attestation=AttestationConveyancePreference.NONE,
        verify_origin=lambda origin: origin in origins,
    )


def credential_data(records: Iterable):
    return [
        AttestedCredentialData(bytes(record.credential_data))
        for record in records
    ]


def registration_options(user, records):
    server = get_server()
    options, state = server.register_begin(
        {
            "id": str(user.pk).encode("ascii"),
            "name": user.get_username(),
            "displayName": user.get_full_name() or user.get_username(),
        },
        credential_data(records),
        resident_key_requirement=ResidentKeyRequirement.DISCOURAGED,
        user_verification=UserVerificationRequirement.PREFERRED,
        authenticator_attachment=AuthenticatorAttachment.CROSS_PLATFORM,
    )
    return server, dict(options), state


def authentication_options(records):
    server = get_server()
    options, state = server.authenticate_begin(
        credential_data(records),
        user_verification=UserVerificationRequirement.PREFERRED,
    )
    return server, dict(options), state


def save_state(request, key, state, *, user_id, extra=None):
    request.session[key] = {
        "state": state,
        "user_id": user_id,
        "created_at": time.time(),
        "extra": extra or {},
    }
    request.session.modified = True


def consume_state(request, key, *, user_id):
    envelope = request.session.pop(key, None)
    request.session.modified = True
    if not envelope or envelope.get("user_id") != user_id:
        raise WebAuthnStateError("WebAuthn setup session is missing or invalid.")
    created_at = envelope.get("created_at")
    ttl = settings.WEBAUTHN_CHALLENGE_TTL_SECONDS
    if not isinstance(ttl, int) or not 30 <= ttl <= 600:
        raise WebAuthnConfigurationError(
            "WebAuthn challenge TTL must be between 30 and 600 seconds."
        )
    age = time.time() - created_at if isinstance(created_at, (int, float)) else -1
    if age < 0 or age > ttl:
        raise WebAuthnStateError("WebAuthn challenge has expired.")
    return envelope["state"], envelope.get("extra") or {}
