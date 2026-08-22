# YubiKey and WebAuthn operations

WAFControl supports YubiKey and other cross-platform FIDO2/WebAuthn security
keys as a second factor after the account password. TOTP remains available as
an independent fallback when enabled.

## Security model

- The password is always verified first.
- Registration and deletion require the current password again.
- Registration and authentication use short-lived, single-use challenges.
- The relying-party ID and accepted HTTPS origins are explicit configuration.
- User presence is mandatory; user verification is requested when available.
- Discoverable credentials are discouraged because the key is a second factor,
  not a password replacement.
- Attestation is set to `none`. WAFControl verifies the credential and
  signature but does not collect vendor attestation or claim that a key is
  manufactured by Yubico.
- A non-zero authenticator signature counter must advance. A stagnant counter
  is rejected as a possible cloned credential. Authenticators that always
  return zero remain compatible, as required by WebAuthn.
- Credentials are scoped to one Django user and credential IDs are globally
  unique.
- Registration, deletion and authentication outcomes are written to the
  WAFControl audit log without storing challenges or passwords there.

## Required production configuration

For the Ironitia dashboard on `https://ironitia.com:7000`:

```dotenv
WEBAUTHN_RP_ID=ironitia.com
WEBAUTHN_RP_NAME="OWASP WAFControl"
WEBAUTHN_ALLOWED_ORIGINS=https://ironitia.com:7000
WEBAUTHN_CHALLENGE_TTL_SECONDS=300
```

The RP ID contains no scheme or port. Every allowed origin contains the scheme,
host and port, with no trailing slash. Do not add wildcard origins.

After changing the environment, restart Gunicorn and verify that the browser
uses exactly the configured HTTPS URL. WebAuthn does not work through an IP
address when the credential was registered for the DNS RP ID.

## Deployment order

1. Back up PostgreSQL and the application.
2. Install the pinned dependencies from `requirements.txt`.
3. Add the four `WEBAUTHN_*` settings to the root-owned `.env`.
4. Run `python manage.py migrate`; migration `0007` creates the credential
   table.
5. Run `python manage.py check --deploy` and the complete test suite.
6. Restart `wafcontrol.service`; Celery does not handle WebAuthn.
7. Confirm the profile page contains the **YubiKey / Security Key** tab.
8. Register a test key, sign out, and complete a real password-plus-key login.
9. Confirm registration and authentication audit entries.
10. Keep TOTP enabled or register a second key before relying on a single key.

## Enrolment

Open `Dashboard → Profile → YubiKey / Security Key`, enter a descriptive key
name and the current password, then select **Add security key**. Insert/touch
the YubiKey and follow the browser prompt. A configured PIN may be requested.

The browser and WAFControl must remain on the same HTTPS origin for both
registration and future authentication.

## Loss and recovery

A user can remove a registered key from the profile by entering the current
password. Losing the only key does not create a bypass:

- use the TOTP fallback if it is enabled;
- use a separately registered backup security key; or
- have an authorised database administrator remove only the lost credential
  after identity verification and a database backup.

Administrative recovery must be audited. Never disable WebAuthn validation or
alter RP/origin checks to recover an account.

## Database recovery command

After identity verification, list only non-secret metadata:

```bash
/opt/WafControl/venv/bin/python manage.py shell -c \
  'from wafinstaller.models import WebAuthnCredential; print(list(WebAuthnCredential.objects.values("id", "user__username", "name", "created_at", "last_used_at")))'
```

Removal should use the profile interface whenever possible. If emergency
database removal is necessary, back up PostgreSQL first and delete by the exact
numeric credential ID, never by a broad user or table query.

## Browser compatibility

A secure context and WebAuthn-capable browser are required. The implementation
uses standard `navigator.credentials.create()` and
`navigator.credentials.get()` calls and does not require a Yubico cloud
service. USB and NFC transports are recorded when the browser reports them;
these values are informational and are not trusted for authentication.
