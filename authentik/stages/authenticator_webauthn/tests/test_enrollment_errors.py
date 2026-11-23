"""Rendered semantic errors support recovery without matching message text."""

from datetime import datetime
from unittest.mock import patch

from django.urls import reverse
from rest_framework.test import APITestCase
from webauthn.helpers.base64url_to_bytes import base64url_to_bytes

from authentik.core.tests.utils import create_test_user
from authentik.stages.authenticator_webauthn.tests import test_enrollment as helpers


class TestEnrollmentErrors(APITestCase):
    setUp = helpers.TestWebAuthnEnrollment.setUp
    tearDown = helpers.TestWebAuthnEnrollment.tearDown
    begin = helpers.TestWebAuthnEnrollment.begin
    complete = helpers.TestWebAuthnEnrollment.complete
    credential_response = helpers.TestWebAuthnEnrollment.credential_response

    def assert_error(self, response, code):
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["code"], code)
        self.assertIsInstance(response.json()["detail"], str)

    def test_changed_begin_binding_reports_conflict_and_preserves_original(self):
        begun = self.begin()
        self.assert_error(self.begin(user=create_test_user()), "idempotency_conflict")
        self.assertEqual(self.begin().data, begun.data)

    def action(self, begun, name):
        return self.client.post(
            reverse(
                f"authentik_api:admin-webauthnenrollment-{name}",
                kwargs={"pk": begun.data["pk"]},
            ),
            {},
            format="json",
        )

    def test_cancelled_and_completed_attempts_have_stable_codes(self):
        cancelled = self.begin(key="cancelled")
        _, response = self.credential_response(cancelled)
        self.assertEqual(self.action(cancelled, "cancel").status_code, 200)
        self.assert_error(self.complete(cancelled.data["pk"], response), "enrollment_cancelled")
        self.assert_error(self.begin(key="cancelled"), "enrollment_cancelled")
        completed = self.begin(key="completed")
        _, response = self.credential_response(completed)
        accepted = self.complete(completed.data["pk"], response)
        self.assertEqual(accepted.status_code, 200)
        self.assert_error(
            self.complete(completed.data["pk"], {**response, "changed": True}),
            "enrollment_completed",
        )
        self.assert_error(self.action(completed, "cancel"), "enrollment_completed")
        self.assert_error(self.begin(key="completed"), "enrollment_completed")
        self.assertEqual(self.complete(completed.data["pk"], response).data, accepted.data)

    def test_expiry_code_is_stable_before_and_after_persisted_expiry(self):
        begun = self.begin()
        _, response = self.credential_response(begun)
        deadline = datetime.fromisoformat(begun.data["expires"].replace("Z", "+00:00"))
        with patch(
            "authentik.stages.authenticator_webauthn.api.enrollment.now", return_value=deadline
        ):
            self.assert_error(self.begin(), "enrollment_expired")
            for _ in range(2):
                self.assert_error(self.complete(begun.data["pk"], response), "enrollment_expired")
            inspected = self.client.get(
                reverse(
                    "authentik_api:admin-webauthnenrollment-detail",
                    kwargs={"pk": begun.data["pk"]},
                )
            )
            self.assertEqual(inspected.data["status"], "expired")
            self.assertIsNone(inspected.data["device"])

    def test_invalid_credential_is_correctable_on_same_attempt(self):
        begun = self.begin()
        _, invalid = self.credential_response(begun, valid_signature=False)
        self.assert_error(self.complete(begun.data["pk"], invalid), "credential_invalid")
        _, valid = self.credential_response(begun)
        self.assertEqual(self.complete(begun.data["pk"], valid).status_code, 200)

    def test_revoked_result_cannot_be_recreated(self):
        begun = self.begin()
        _, response = self.credential_response(begun)
        accepted = self.complete(begun.data["pk"], response)
        url = reverse(
            "authentik_api:admin-webauthndevice-detail", kwargs={"pk": accepted.data["device"]}
        )
        self.assertEqual(self.client.delete(url).status_code, 204)
        self.assert_error(self.complete(begun.data["pk"], response), "credential_revoked")
        self.assertEqual(self.client.get(url).status_code, 404)

    def test_duplicate_credential_does_not_consume_new_attempt(self):
        first = self.begin(key="first")
        credential, response = self.credential_response(first)
        self.assertEqual(self.complete(first.data["pk"], response).status_code, 200)
        second = self.begin(key="second")
        duplicate = credential.registration_response(
            base64url_to_bytes(second.data["registration"]["challenge"])
        )
        self.assert_error(self.complete(second.data["pk"], duplicate), "credential_exists")
        _, replacement = self.credential_response(second)
        self.assertEqual(self.complete(second.data["pk"], replacement).status_code, 200)
