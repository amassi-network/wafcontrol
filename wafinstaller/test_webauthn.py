import json
import time
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.contrib.auth import get_user_model
from django.test import Client, TestCase, override_settings
from django.urls import reverse

from wafinstaller.models import AuditEntry, WebAuthnCredential
from wafinstaller.webauthn_service import (
    AUTHENTICATION_SESSION_KEY,
    REGISTRATION_SESSION_KEY,
)


class FakeCredentialData(bytes):
    def __new__(cls, value, credential_id):
        instance = super().__new__(cls, value)
        instance.credential_id = credential_id
        return instance


@override_settings(
    WEBAUTHN_RP_ID="testserver",
    WEBAUTHN_RP_NAME="WAFControl tests",
    WEBAUTHN_ALLOWED_ORIGINS=["https://testserver"],
    WEBAUTHN_CHALLENGE_TTL_SECONDS=300,
)
class WebAuthnProfileTests(TestCase):
    def setUp(self):
        self.password = "correct horse battery staple"
        self.user = get_user_model().objects.create_user(
            username="security-admin",
            email="admin@example.test",
            password=self.password,
            is_staff=True,
            is_superuser=True,
        )
        self.client.force_login(self.user)

    def _set_state(self, key, *, extra=None):
        session = self.client.session
        session[key] = {
            "state": {"challenge": "challenge"},
            "user_id": self.user.pk,
            "created_at": time.time(),
            "extra": extra or {},
        }
        session.save()

    def test_profile_exposes_yubikey_tab(self):
        response = self.client.get(
            reverse("wafinstaller:admin_profile") + "?tab=yubikey"
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "YubiKey / Security Key")
        self.assertContains(response, "Add security key")

    @patch("wafinstaller.webauthn_views.registration_options")
    def test_registration_begin_requires_password_and_stores_challenge(
        self, registration_options
    ):
        registration_options.return_value = (
            Mock(),
            {"publicKey": {"challenge": "challenge"}},
            {"challenge": "challenge"},
        )

        response = self.client.post(
            reverse("wafinstaller:yubikey_registration_options"),
            data={"name": "Main YubiKey", "current_password": self.password},
        )

        self.assertEqual(response.status_code, 200)
        state = self.client.session[REGISTRATION_SESSION_KEY]
        self.assertEqual(state["user_id"], self.user.pk)
        self.assertEqual(state["extra"]["name"], "Main YubiKey")
        audit = AuditEntry.objects.get(action="admin.webauthn.register.begin")
        self.assertEqual(audit.outcome, AuditEntry.Outcome.SUCCEEDED)

    @patch("wafinstaller.webauthn_views.registration_options")
    def test_registration_begin_rejects_wrong_password(self, registration_options):
        response = self.client.post(
            reverse("wafinstaller:yubikey_registration_options"),
            data={"name": "Main YubiKey", "current_password": "wrong"},
        )

        self.assertEqual(response.status_code, 400)
        registration_options.assert_not_called()
        self.assertNotIn(REGISTRATION_SESSION_KEY, self.client.session)

    @patch("wafinstaller.webauthn_views.get_server")
    def test_registration_complete_persists_credential_and_consumes_state(
        self, get_server
    ):
        self._set_state(
            REGISTRATION_SESSION_KEY,
            extra={"name": "Main YubiKey"},
        )
        registered = FakeCredentialData(b"credential-data", b"credential-id")
        get_server.return_value.register_complete.return_value = SimpleNamespace(
            credential_data=registered,
            counter=5,
        )

        response = self.client.post(
            reverse("wafinstaller:yubikey_registration_complete"),
            data=json.dumps(
                {
                    "credential": {
                        "id": "credential-id",
                        "response": {"transports": ["usb", "nfc", "invalid"]},
                    }
                }
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        credential = WebAuthnCredential.objects.get(user=self.user)
        self.assertEqual(credential.name, "Main YubiKey")
        self.assertEqual(bytes(credential.credential_id), b"credential-id")
        self.assertEqual(credential.sign_count, 5)
        self.assertEqual(credential.transports, ["nfc", "usb"])
        self.assertNotIn(REGISTRATION_SESSION_KEY, self.client.session)

    @patch("wafinstaller.webauthn_views.get_server")
    def test_registration_challenge_cannot_be_reused(self, get_server):
        self._set_state(
            REGISTRATION_SESSION_KEY,
            extra={"name": "Main YubiKey"},
        )
        get_server.return_value.register_complete.side_effect = ValueError("bad")

        first = self.client.post(
            reverse("wafinstaller:yubikey_registration_complete"),
            data=json.dumps({"credential": {"response": {}}}),
            content_type="application/json",
        )
        second = self.client.post(
            reverse("wafinstaller:yubikey_registration_complete"),
            data=json.dumps({"credential": {"response": {}}}),
            content_type="application/json",
        )

        self.assertEqual(first.status_code, 400)
        self.assertEqual(second.status_code, 400)
        self.assertEqual(get_server.return_value.register_complete.call_count, 1)

    def test_delete_requires_current_password(self):
        credential = WebAuthnCredential.objects.create(
            user=self.user,
            name="Backup key",
            credential_id=b"delete-id",
            credential_data=b"delete-data",
        )
        url = reverse("wafinstaller:yubikey_delete", args=(credential.pk,))

        denied = self.client.post(url, {"current_password": "wrong"})
        accepted = self.client.post(url, {"current_password": self.password})

        self.assertEqual(denied.status_code, 400)
        self.assertEqual(accepted.status_code, 200)
        self.assertFalse(WebAuthnCredential.objects.filter(pk=credential.pk).exists())

    def test_mutation_endpoints_require_csrf(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)
        endpoints = (
            reverse("wafinstaller:yubikey_registration_options"),
            reverse("wafinstaller:yubikey_registration_complete"),
        )
        for endpoint in endpoints:
            with self.subTest(endpoint=endpoint):
                response = client.post(
                    endpoint,
                    data="{}",
                    content_type="application/json",
                )
                self.assertEqual(response.status_code, 403)


@override_settings(
    WEBAUTHN_RP_ID="testserver",
    WEBAUTHN_RP_NAME="WAFControl tests",
    WEBAUTHN_ALLOWED_ORIGINS=["https://testserver"],
    WEBAUTHN_CHALLENGE_TTL_SECONDS=300,
)
class WebAuthnLoginTests(TestCase):
    def setUp(self):
        self.password = "correct horse battery staple"
        self.user = get_user_model().objects.create_user(
            username="login-admin",
            password=self.password,
            is_staff=True,
            is_superuser=True,
        )
        self.credential = WebAuthnCredential.objects.create(
            user=self.user,
            name="Login key",
            credential_id=b"login-id",
            credential_data=b"login-data",
            sign_count=4,
        )

    def _set_pre_authentication_state(self):
        session = self.client.session
        session["pre_2fa_user_id"] = self.user.pk
        session[AUTHENTICATION_SESSION_KEY] = {
            "state": {"challenge": "challenge"},
            "user_id": self.user.pk,
            "created_at": time.time(),
            "extra": {},
        }
        session.save()

    def test_password_login_redirects_to_second_factor_when_key_exists(self):
        response = self.client.post(
            reverse("wafinstaller:login"),
            {"username": self.user.username, "password": self.password},
        )

        self.assertRedirects(
            response,
            reverse("wafinstaller:verify_2fa"),
            fetch_redirect_response=False,
        )
        self.assertNotIn("_auth_user_id", self.client.session)

    @patch("wafinstaller.webauthn_views.authentication_options")
    def test_authentication_begin_requires_completed_password_step(
        self, authentication_options
    ):
        no_password = self.client.post(
            reverse("wafinstaller:yubikey_authentication_options"),
            data="{}",
            content_type="application/json",
        )
        session = self.client.session
        session["pre_2fa_user_id"] = self.user.pk
        session.save()
        authentication_options.return_value = (
            Mock(),
            {"publicKey": {"challenge": "challenge"}},
            {"challenge": "challenge"},
        )
        after_password = self.client.post(
            reverse("wafinstaller:yubikey_authentication_options"),
            data="{}",
            content_type="application/json",
        )

        self.assertEqual(no_password.status_code, 401)
        self.assertEqual(after_password.status_code, 200)
        self.assertIn(AUTHENTICATION_SESSION_KEY, self.client.session)

    @patch("wafinstaller.webauthn_views.AuthenticationResponse.from_dict")
    @patch("wafinstaller.webauthn_views.credential_data")
    @patch("wafinstaller.webauthn_views.get_server")
    def test_security_key_completes_login_and_advances_counter(
        self, get_server, credential_data, response_from_dict
    ):
        self._set_pre_authentication_state()
        credential_data.return_value = [Mock()]
        get_server.return_value.authenticate_complete.return_value = SimpleNamespace(
            credential_id=b"login-id"
        )
        response_from_dict.return_value = SimpleNamespace(
            response=SimpleNamespace(
                authenticator_data=SimpleNamespace(counter=5)
            )
        )

        response = self.client.post(
            reverse("wafinstaller:yubikey_authentication_complete"),
            data=json.dumps({"id": "login-id", "response": {}}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(int(self.client.session["_auth_user_id"]), self.user.pk)
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.sign_count, 5)
        self.assertIsNotNone(self.credential.last_used_at)
        self.assertNotIn("pre_2fa_user_id", self.client.session)

    @patch("wafinstaller.webauthn_views.AuthenticationResponse.from_dict")
    @patch("wafinstaller.webauthn_views.credential_data")
    @patch("wafinstaller.webauthn_views.get_server")
    def test_non_advancing_counter_is_rejected(
        self, get_server, credential_data, response_from_dict
    ):
        self._set_pre_authentication_state()
        credential_data.return_value = [Mock()]
        get_server.return_value.authenticate_complete.return_value = SimpleNamespace(
            credential_id=b"login-id"
        )
        response_from_dict.return_value = SimpleNamespace(
            response=SimpleNamespace(
                authenticator_data=SimpleNamespace(counter=4)
            )
        )

        response = self.client.post(
            reverse("wafinstaller:yubikey_authentication_complete"),
            data=json.dumps({"id": "login-id", "response": {}}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 400)
        self.assertNotIn("_auth_user_id", self.client.session)
        self.credential.refresh_from_db()
        self.assertEqual(self.credential.sign_count, 4)
