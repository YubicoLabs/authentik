"""Enrollment status and retries remain available until record retention ends."""

from contextlib import contextmanager
from datetime import datetime, timedelta
from unittest.mock import patch

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.tasks import clean_expired_models
from authentik.core.tests.utils import create_test_admin_user
from authentik.lib.config import CONFIG
from authentik.stages.authenticator_webauthn.models import WebAuthnEnrollment
from authentik.stages.authenticator_webauthn.tests import test_enrollment as helpers


class TestEnrollmentRetention(APITestCase):
    setUp = helpers.TestWebAuthnEnrollment.setUp
    begin = helpers.TestWebAuthnEnrollment.begin
    complete = helpers.TestWebAuthnEnrollment.complete
    credential_response = helpers.TestWebAuthnEnrollment.credential_response

    @contextmanager
    def clock(self, instant):
        with (
            patch(
                "authentik.stages.authenticator_webauthn.api.enrollment.now", return_value=instant
            ),
            patch("authentik.lib.models.now", return_value=instant),
            patch("authentik.core.tasks.now", return_value=instant),
        ):
            yield

    def detail(self, pk):
        return self.client.get(
            reverse("authentik_api:admin-webauthnenrollment-detail", kwargs={"pk": pk})
        )

    def test_completed_result_is_retained_for_30_days_after_deadline(self):
        self.client.force_authenticate(self.admin)
        begun = self.begin()
        _, response = self.credential_response(begun)
        completed = self.complete(begun.data["pk"], response)
        self.assertEqual(completed.status_code, 200)
        deadline = datetime.fromisoformat(begun.data["expires"].replace("Z", "+00:00"))
        with self.clock(deadline + timedelta(days=30) - timedelta(seconds=1)):
            clean_expired_models.send()
            self.assertEqual(self.complete(begun.data["pk"], response).status_code, 200)
        with self.clock(deadline + timedelta(days=30, seconds=1)):
            clean_expired_models.send()
            self.assertFalse(
                WebAuthnEnrollment.objects.including_expired().filter(pk=begun.data["pk"]).exists()
            )
            self.assertEqual(self.detail(begun.data["pk"]).status_code, 404)
            self.assertEqual(self.complete(begun.data["pk"], response).status_code, 404)
            device = self.client.get(
                reverse(
                    "authentik_api:admin-webauthndevice-detail",
                    kwargs={"pk": completed.data["device"]},
                )
            )
            self.assertEqual(device.status_code, 200)

    def test_retention_cutoff_hides_records_before_worker_cleanup(self):
        self.client.force_authenticate(self.admin)
        begun = self.begin()
        deadline = datetime.fromisoformat(begun.data["expires"].replace("Z", "+00:00"))
        with self.clock(deadline + timedelta(days=30, seconds=1)):
            self.assertEqual(self.detail(begun.data["pk"]).status_code, 404)
            listed = self.client.get(reverse("authentik_api:admin-webauthnenrollment-list"))
            self.assertEqual(listed.data["results"], [])

    def test_expired_idempotency_key_rejects_until_cleanup_without_affecting_other_callers(self):
        self.client.force_authenticate(self.admin)
        begun = self.begin()
        deadline = datetime.fromisoformat(begun.data["expires"].replace("Z", "+00:00"))
        with self.clock(deadline + timedelta(days=30, seconds=1)):
            rejected = self.begin()
            self.assertEqual(rejected.status_code, 400)
            self.assertEqual(rejected.data["code"], "enrollment_expired")
            self.assertEqual(self.begin(key="fresh-request").status_code, 201)
            self.client.force_authenticate(create_test_admin_user())
            other = self.begin()
            self.assertEqual(other.status_code, 201)
            self.assertNotEqual(other.data["pk"], begun.data["pk"])
            clean_expired_models.send()
            self.assertEqual(self.detail(other.data["pk"]).status_code, 200)
            self.client.force_authenticate(self.admin)
            replacement = self.begin()
            self.assertEqual(replacement.status_code, 201)
            self.assertNotEqual(replacement.data["pk"], begun.data["pk"])

    def test_pending_and_cancelled_records_remain_until_retention_ends(self):
        self.client.force_authenticate(self.admin)
        pending = self.begin(key="pending")
        cancelled = self.begin(key="cancelled")
        self.assertEqual(
            self.client.post(
                reverse(
                    "authentik_api:admin-webauthnenrollment-cancel",
                    kwargs={"pk": cancelled.data["pk"]},
                )
            ).status_code,
            200,
        )
        deadline = datetime.fromisoformat(cancelled.data["expires"].replace("Z", "+00:00"))
        with self.clock(deadline + timedelta(seconds=1)):
            clean_expired_models.send()
            self.assertEqual(self.detail(pending.data["pk"]).data["status"], "expired")
            self.assertEqual(self.detail(cancelled.data["pk"]).data["status"], "cancelled")
        with self.clock(deadline + timedelta(days=30, seconds=1)):
            clean_expired_models.send()
            self.assertEqual(self.detail(pending.data["pk"]).status_code, 404)
            self.assertEqual(self.detail(cancelled.data["pk"]).status_code, 404)

    def test_configured_retention_is_fixed_when_attempt_begins(self):
        self.client.force_authenticate(self.admin)
        with CONFIG.patch("webauthn_enrollment.retention_days", "1"):
            begun = self.begin()
            _, response = self.credential_response(begun)
            self.assertEqual(self.complete(begun.data["pk"], response).status_code, 200)
        deadline = datetime.fromisoformat(begun.data["expires"].replace("Z", "+00:00"))
        with self.clock(deadline + timedelta(hours=23)):
            self.assertEqual(self.complete(begun.data["pk"], response).status_code, 200)
        with self.clock(deadline + timedelta(days=1, seconds=1)):
            self.assertEqual(self.complete(begun.data["pk"], response).status_code, 404)

    def test_zero_retention_ends_at_enrollment_deadline(self):
        self.client.force_authenticate(self.admin)
        with CONFIG.patch("webauthn_enrollment.retention_days", 0):
            begun = self.begin()
        self.assertEqual(begun.status_code, 201)
        deadline = datetime.fromisoformat(begun.data["expires"].replace("Z", "+00:00"))
        with self.clock(deadline - timedelta(seconds=1)):
            self.assertEqual(self.detail(begun.data["pk"]).status_code, 200)
        with self.clock(deadline + timedelta(seconds=1)):
            self.assertEqual(self.detail(begun.data["pk"]).status_code, 404)
            clean_expired_models.send()
            self.assertFalse(
                WebAuthnEnrollment.objects.including_expired().filter(pk=begun.data["pk"]).exists()
            )

    def test_invalid_retention_does_not_create_an_attempt(self):
        for value in (-1, True, 1.5, "1.5", "invalid", 10**30):
            with (
                self.subTest(value=value),
                CONFIG.patch("webauthn_enrollment.retention_days", value),
            ):
                rejected = self.begin()
                self.assertEqual(rejected.status_code, 400)
                self.assertIn("AUTHENTIK_WEBAUTHN_ENROLLMENT__RETENTION_DAYS", str(rejected.data))
                self.assertEqual(
                    self.client.get(reverse("authentik_api:admin-webauthnenrollment-list")).data[
                        "results"
                    ],
                    [],
                )
        self.assertEqual(self.begin().status_code, 201)
