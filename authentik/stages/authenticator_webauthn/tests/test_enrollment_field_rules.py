"""Effective enrollment status respects native response field policies."""

from datetime import timedelta
from unittest.mock import patch

from django.urls import reverse
from django.utils.timezone import now
from rest_framework.test import APITestCase

from authentik.core.tests.utils import create_test_admin_user
from authentik.rbac.apps import EnableCustomPermissions
from authentik.rbac.models import PermissionCheck
from authentik.stages.authenticator_webauthn.tests import test_enrollment as helpers
from authentik.stages.authenticator_webauthn.tests import (
    test_enrollment_authorization as auth_helpers,
)


class TestEnrollmentFieldRules(APITestCase):
    """Check list and retrieve using a scoped service account, not a superuser."""

    setUp = auth_helpers.TestEnrollmentAuthorization.setUp
    restore_origin = auth_helpers.TestEnrollmentAuthorization.restore_origin
    begin = helpers.TestWebAuthnEnrollment.begin

    def test_hidden_status_stays_hidden_after_expiry(self):
        previous = EnableCustomPermissions.get()
        EnableCustomPermissions.set(True)
        self.addCleanup(EnableCustomPermissions.set, previous)
        PermissionCheck.objects.create(
            name="enrollment-status",
            endpoints=[
                "authenticators/admin/webauthn-enrollments:list",
                "authenticators/admin/webauthn-enrollments:retrieve",
            ],
            expression="def hidden_fields(request, obj):\n    return {'status'}",
        )
        begun = self.begin()
        self.assertEqual(begun.status_code, 201)
        detail = reverse(
            "authentik_api:admin-webauthnenrollment-detail", kwargs={"pk": begun.data["pk"]}
        )
        listing = reverse("authentik_api:admin-webauthnenrollment-list")
        for instant in (now(), now() + timedelta(minutes=10)):
            with (
                self.subTest(instant=instant),
                patch(
                    "authentik.stages.authenticator_webauthn.api.enrollment.now",
                    return_value=instant,
                ),
            ):
                result = self.client.get(detail)
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.json()["status"], "")
                result = self.client.get(listing)
                self.assertEqual(result.status_code, 200)
                self.assertEqual(result.json()["results"][0]["status"], "")

        self.client.force_login(create_test_admin_user())
        with patch(
            "authentik.stages.authenticator_webauthn.api.enrollment.now",
            return_value=now() + timedelta(minutes=10),
        ):
            result = self.client.get(detail)
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.json()["status"], "expired")
