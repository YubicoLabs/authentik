"""Authorization is checked again at completion, including successful replays.

These are sequential revocation boundaries, not claims that an in-flight request
is aborted when its caller's permissions change after authorization.
"""

from django.urls import reverse
from rest_framework.test import APITestCase
from webauthn.helpers.base64url_to_bytes import base64url_to_bytes

from authentik.core.models import Token, TokenIntents, UserTypes
from authentik.core.tests.utils import create_test_admin_user, create_test_user
from authentik.lib.config import CONFIG, UNSET
from authentik.lib.generators import generate_id
from authentik.stages.authenticator_webauthn.models import AuthenticatorWebAuthnStage
from authentik.stages.authenticator_webauthn.tests.test_enrollment import (
    SoftwareES256Credential,
)

APP = "authentik_stages_authenticator_webauthn"


class TestEnrollmentAuthorization(APITestCase):
    """A previously issued challenge does not preserve revoked authority."""

    def setUp(self):
        self.previous_origin = CONFIG.get("webauthn_enrollment.origin", default=UNSET)
        CONFIG.set("webauthn_enrollment.origin", "https://testserver")
        self.addCleanup(self.restore_origin)
        self.caller = create_test_user(type=UserTypes.SERVICE_ACCOUNT)
        self.user = create_test_user()
        self.stage = AuthenticatorWebAuthnStage.objects.create(name=generate_id())
        self.caller.assign_perms_to_managed_role(
            [
                f"{APP}.add_webauthnenrollment",
                f"{APP}.change_webauthnenrollment",
                f"{APP}.view_webauthnenrollment",
            ]
        )
        self.caller.assign_perms_to_managed_role("authentik_core.enroll_user_webauthn", self.user)
        self.caller.assign_perms_to_managed_role("authentik_core.view_user", self.user)
        self.caller.assign_perms_to_managed_role(
            f"{APP}.view_authenticatorwebauthnstage", self.stage
        )
        # Session authentication reloads the caller for every HTTP request; do
        # not force-authenticate a stale User carrying a permission cache.
        self.client.force_login(self.caller)

    def begin_for(self, user):
        return self.client.post(
            reverse("authentik_api:admin-webauthnenrollment-begin"),
            {"user": user.pk, "stage": str(self.stage.pk), "idempotency_key": generate_id()},
            format="json",
        )

    def test_view_and_device_creation_permissions_do_not_grant_enrollment_authority(self):
        self.caller.remove_perms_from_managed_role("authentik_core.enroll_user_webauthn", self.user)
        self.caller.assign_perms_to_managed_role(f"{APP}.add_webauthndevice")
        self.assertEqual(self.begin_for(self.user).status_code, 403)

    def test_enrollment_authority_is_scoped_to_the_target_user(self):
        other = create_test_user()
        self.caller.assign_perms_to_managed_role("authentik_core.view_user", other)
        self.assertEqual(self.begin_for(other).status_code, 403)
        self.assertEqual(self.begin_for(self.user).status_code, 201)
        self.caller.assign_perms_to_managed_role("authentik_core.enroll_user_webauthn", other)
        self.assertEqual(self.begin_for(other).status_code, 201)

    def test_global_enrollment_authority_still_requires_target_visibility(self):
        other = create_test_user()
        self.caller.assign_perms_to_managed_role("authentik_core.enroll_user_webauthn")
        self.assertEqual(self.begin_for(other).status_code, 403)
        self.caller.assign_perms_to_managed_role("authentik_core.view_user", other)
        self.assertEqual(self.begin_for(other).status_code, 201)

    def test_issuer_can_cancel_after_losing_enrollment_authority(self):
        original = self.prepare(completed=False)
        self.caller.remove_perms_from_managed_role("authentik_core.enroll_user_webauthn", self.user)
        self.assertEqual(self.complete().status_code, 403)
        cancelled = self.client.post(
            reverse("authentik_api:admin-webauthnenrollment-cancel", kwargs={"pk": original["pk"]})
        )
        self.assertEqual(cancelled.status_code, 200)
        self.assertEqual(cancelled.data["status"], "cancelled")

    def restore_origin(self):
        if self.previous_origin is UNSET:
            CONFIG.delete("webauthn_enrollment.origin")
        else:
            CONFIG.set("webauthn_enrollment.origin", self.previous_origin)

    def prepare(self, completed):
        begun = self.client.post(
            reverse("authentik_api:admin-webauthnenrollment-begin"),
            {"user": self.user.pk, "stage": str(self.stage.pk), "idempotency_key": generate_id()},
            format="json",
        )
        self.assertEqual(begun.status_code, 201)
        self.detail_url = reverse(
            "authentik_api:admin-webauthnenrollment-detail", kwargs={"pk": begun.data["pk"]}
        )
        self.complete_url = reverse(
            "authentik_api:admin-webauthnenrollment-complete",
            kwargs={"pk": begun.data["pk"]},
        )
        credential = SoftwareES256Credential(begun.data["rp_id"], begun.data["origin"])
        self.body = {
            "response": credential.registration_response(
                base64url_to_bytes(begun.data["registration"]["challenge"])
            )
        }
        if completed:
            accepted = self.complete()
            self.assertEqual(accepted.status_code, 200)
        inspected = self.client.get(self.detail_url)
        self.assertEqual(inspected.status_code, 200)
        return inspected.data

    def complete(self):
        return self.client.post(self.complete_url, self.body, format="json")

    def test_api_token_revocation_and_rotation_preserve_attempt_ownership(self):
        self.client.logout()
        token = Token.objects.create(
            identifier=generate_id(),
            user=self.caller,
            intent=TokenIntents.INTENT_API,
            expiring=False,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {token.key}")
        original = self.prepare(completed=False)
        token.delete()
        self.assertEqual(self.complete().status_code, 403)
        replacement = Token.objects.create(
            identifier=generate_id(),
            user=self.caller,
            intent=TokenIntents.INTENT_API,
            expiring=False,
        )
        self.client.credentials(HTTP_AUTHORIZATION=f"Bearer {replacement.key}")
        self.assertEqual(self.client.get(self.detail_url).data, original)
        completed = self.complete()
        self.assertEqual(completed.status_code, 200)
        self.assertEqual(completed.data["status"], "completed")
        self.assertEqual(self.complete().data, completed.data)

    def assert_rejected_without_changing_attempt(self, expected_status, original):
        rejected = self.complete()
        self.assertEqual(rejected.status_code, expected_status)
        inspected = self.client.get(self.detail_url)
        self.assertEqual(inspected.status_code, 200)
        self.assertEqual(inspected.data, original)

    def permission_revocation(self, permission, obj=None):
        for completed in (False, True):
            with self.subTest(completed=completed):
                original = self.prepare(completed)
                self.caller.remove_perms_from_managed_role(permission, obj)
                try:
                    self.assert_rejected_without_changing_attempt(403, original)
                finally:
                    self.caller.assign_perms_to_managed_role(permission, obj)
                accepted = self.complete()
                self.assertEqual(accepted.status_code, 200)
                self.assertEqual(accepted.data["status"], "completed")
                if completed:
                    self.assertEqual(accepted.data, original)
                replay = self.complete()
                self.assertEqual(replay.status_code, 200)
                self.assertEqual(replay.data, accepted.data)

    def test_revoked_completion_permission_blocks_completion_and_replay(self):
        self.permission_revocation(f"{APP}.change_webauthnenrollment")

    def test_revoked_enrollment_authority_blocks_completion_and_replay(self):
        self.permission_revocation("authentik_core.enroll_user_webauthn", self.user)

    def test_revoked_target_access_blocks_completion_and_replay(self):
        self.permission_revocation("authentik_core.view_user", self.user)

    def test_revoked_stage_access_blocks_completion_and_replay(self):
        self.permission_revocation(f"{APP}.view_authenticatorwebauthnstage", self.stage)

    def test_deleted_stage_does_not_bypass_remaining_replay_authority(self):
        original = self.prepare(completed=True)
        self.client.force_login(create_test_admin_user())
        deleted = self.client.delete(
            reverse("authentik_api:authenticatorwebauthnstage-detail", kwargs={"pk": self.stage.pk})
        )
        self.assertEqual(deleted.status_code, 204)
        self.client.force_login(self.caller)
        replay = self.complete()
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.data["device"], original["device"])
        self.assertIsNone(replay.data["stage"])
        for permission, obj in (
            ("authentik_core.view_user", self.user),
            (f"{APP}.change_webauthnenrollment", None),
        ):
            with self.subTest(permission=permission):
                self.caller.remove_perms_from_managed_role(permission, obj)
                try:
                    self.assertEqual(self.complete().status_code, 403)
                finally:
                    self.caller.assign_perms_to_managed_role(permission, obj)

    def test_disabled_target_blocks_completion_and_replay(self):
        for completed in (False, True):
            with self.subTest(completed=completed):
                original = self.prepare(completed)
                self.user.is_active = False
                self.user.save(update_fields=["is_active"])
                try:
                    self.assert_rejected_without_changing_attempt(400, original)
                finally:
                    self.user.is_active = True
                    self.user.save(update_fields=["is_active"])
                accepted = self.complete()
                self.assertEqual(accepted.status_code, 200)
                self.assertEqual(accepted.data["status"], "completed")
                if completed:
                    self.assertEqual(accepted.data, original)
