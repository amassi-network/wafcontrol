from datetime import timedelta

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import Client, SimpleTestCase, TestCase
from django.urls import reverse
from django.utils import timezone

from wafinstaller.helper.helpers import (
    compare_crs_versions,
    get_crs_version_status,
    get_latest_crs_version,
    is_crs_update_available,
    normalize_version,
    select_latest_crs_version,
)
from wafinstaller.models import CrsVersion


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

    def test_crs_mutation_endpoints_reject_missing_csrf_token(self):
        client = Client(enforce_csrf_checks=True)
        client.force_login(self.user)

        for route_name in (
            "wafinstaller:force_fetch_crs_versions",
            "wafinstaller:update_crs_sync",
            "wafinstaller:switch_crs_version",
        ):
            with self.subTest(route_name=route_name):
                response = client.post(reverse(route_name), {"version": "v4.28.0"})
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
