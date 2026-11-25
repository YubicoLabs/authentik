"""Enrollment recovery when administrators remove policy or identity objects."""

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.tests.utils import create_test_admin_user, create_test_user
from authentik.stages.authenticator_webauthn.models import AuthenticatorWebAuthnStage
from authentik.stages.authenticator_webauthn.tests import test_enrollment as helpers


class TestEnrollmentLifecycle(APITestCase):
    setUp = helpers.TestWebAuthnEnrollment.setUp
    begin = helpers.TestWebAuthnEnrollment.begin
    complete = helpers.TestWebAuthnEnrollment.complete
    credential_response = helpers.TestWebAuthnEnrollment.credential_response

    def delete_stage(self):
        return self.client.delete(
            reverse("authentik_api:authenticatorwebauthnstage-detail", kwargs={"pk": self.stage.pk})
        )

    def test_deleted_stage_preserves_completed_result_and_retry(self):
        begun = self.begin()
        _, response = self.credential_response(begun)
        completed = self.complete(begun.data["pk"], response)
        self.assertEqual(completed.status_code, 200)
        self.assertEqual(self.delete_stage().status_code, 204)
        replay = self.complete(begun.data["pk"], response)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.data["device"], completed.data["device"])
        self.assertIsNone(replay.data["stage"])

    def test_deleted_stage_blocks_pending_completion_but_allows_cancellation(self):
        begun = self.begin()
        _, response = self.credential_response(begun)
        self.assertEqual(self.delete_stage().status_code, 204)
        rejected = self.complete(begun.data["pk"], response)
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(rejected.data["code"], "enrollment_policy_unavailable")
        cancelled = self.client.post(
            reverse(
                "authentik_api:admin-webauthnenrollment-cancel", kwargs={"pk": begun.data["pk"]}
            ),
            {},
            format="json",
        )
        self.assertEqual(cancelled.status_code, 200)
        self.assertEqual(cancelled.data["status"], "cancelled")
        self.assertIsNone(cancelled.data["device"])

    def test_deleted_stage_cannot_be_replaced_on_the_same_attempt(self):
        begun = self.begin()
        self.assertEqual(self.delete_stage().status_code, 204)
        replacement = AuthenticatorWebAuthnStage.objects.create(name="replacement-policy")
        rejected = self.begin(stage=replacement)
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(rejected.data["code"], "idempotency_conflict")
        fresh = self.begin(stage=replacement, key="replacement-attempt")
        self.assertEqual(fresh.status_code, 201)
        self.assertNotEqual(fresh.data["pk"], begun.data["pk"])

    def test_revoked_device_is_not_restored_after_stage_deletion(self):
        begun = self.begin()
        _, response = self.credential_response(begun)
        completed = self.complete(begun.data["pk"], response)
        self.assertEqual(self.delete_stage().status_code, 204)
        device_url = reverse(
            "authentik_api:admin-webauthndevice-detail", kwargs={"pk": completed.data["device"]}
        )
        self.assertEqual(self.client.delete(device_url).status_code, 204)
        rejected = self.complete(begun.data["pk"], response)
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(rejected.data["code"], "credential_revoked")
        self.assertEqual(self.client.get(device_url).status_code, 404)

    def test_deleting_issuer_preserves_completed_result_and_credential(self):
        begun = self.begin()
        _, response = self.credential_response(begun)
        completed = self.complete(begun.data["pk"], response)
        self.client.force_login(create_test_admin_user())
        deleted = self.client.delete(
            reverse("authentik_api:user-detail", kwargs={"pk": self.admin.pk})
        )
        self.assertEqual(deleted.status_code, 204)
        replay = self.complete(begun.data["pk"], response)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.data["device"], completed.data["device"])
        device = self.client.get(
            reverse(
                "authentik_api:admin-webauthndevice-detail", kwargs={"pk": completed.data["device"]}
            )
        )
        self.assertEqual(device.status_code, 200)

    def test_deleting_target_removes_enrollment_and_credential(self):
        begun = self.begin()
        _, response = self.credential_response(begun)
        completed = self.complete(begun.data["pk"], response)
        deleted = self.client.delete(
            reverse("authentik_api:user-detail", kwargs={"pk": self.user.pk})
        )
        self.assertEqual(deleted.status_code, 204)
        self.assertEqual(self.complete(begun.data["pk"], response).status_code, 404)
        device = self.client.get(
            reverse(
                "authentik_api:admin-webauthndevice-detail", kwargs={"pk": completed.data["device"]}
            )
        )
        self.assertEqual(device.status_code, 404)

    def test_deleting_issuer_preserves_pending_attempt_without_transferring_ownership(self):
        begun = self.begin()
        _, response = self.credential_response(begun)
        administrator = create_test_admin_user()
        self.client.force_login(administrator)
        deleted = self.client.delete(
            reverse("authentik_api:user-detail", kwargs={"pk": self.admin.pk})
        )
        self.assertEqual(deleted.status_code, 204)
        detail = reverse(
            "authentik_api:admin-webauthnenrollment-detail", kwargs={"pk": begun.data["pk"]}
        )
        retained = self.client.get(detail)
        self.assertEqual(retained.status_code, 200)
        self.assertEqual(retained.data["status"], "pending")

        replacement = create_test_user()
        replacement.assign_perms_to_managed_role(
            [
                "authentik_stages_authenticator_webauthn.view_webauthnenrollment",
                "authentik_stages_authenticator_webauthn.change_webauthnenrollment",
                "authentik_stages_authenticator_webauthn.view_authenticatorwebauthnstage",
                "authentik_core.view_user",
                "authentik_core.enroll_user_webauthn",
            ]
        )
        self.client.force_login(replacement)
        self.assertEqual(self.client.get(detail).status_code, 200)
        self.assertEqual(self.complete(begun.data["pk"], response).status_code, 404)

        self.client.force_login(administrator)
        self.assertEqual(self.complete(begun.data["pk"], response).status_code, 200)
