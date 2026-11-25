"""Incident recovery does not transfer another issuer's completion authority."""

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.models import UserTypes
from authentik.core.tests.utils import create_test_user
from authentik.stages.authenticator_webauthn.tests import test_enrollment_authorization as helpers

APP = "authentik_stages_authenticator_webauthn"


class TestEnrollmentAdministration(APITestCase):
    setUp = helpers.TestEnrollmentAuthorization.setUp
    restore_origin = helpers.TestEnrollmentAuthorization.restore_origin
    prepare = helpers.TestEnrollmentAuthorization.prepare
    complete = helpers.TestEnrollmentAuthorization.complete

    def test_operator_and_connector_can_inspect_cancel_but_not_complete_another_attempt(self):
        for user_type in (UserTypes.INTERNAL, UserTypes.SERVICE_ACCOUNT):
            with self.subTest(user_type=user_type):
                self.client.force_login(self.caller)
                begun = self.prepare(completed=False)
                operator = create_test_user(type=user_type)
                operator.assign_perms_to_managed_role(
                    [
                        f"{APP}.view_webauthnenrollment",
                        f"{APP}.change_webauthnenrollment",
                        "authentik_core.enroll_user_webauthn",
                        "authentik_core.view_user",
                        f"{APP}.view_authenticatorwebauthnstage",
                    ]
                )
                self.client.force_login(operator)
                detail = self.client.get(self.detail_url)
                self.assertEqual(detail.status_code, 200)
                self.assertNotIn("registration", detail.data)
                listing = self.client.get(reverse("authentik_api:admin-webauthnenrollment-list"))
                self.assertIn(str(begun["pk"]), [str(row["pk"]) for row in listing.data["results"]])
                self.assertEqual(self.complete().status_code, 404)
                cancelled = self.client.post(
                    reverse(
                        "authentik_api:admin-webauthnenrollment-cancel", kwargs={"pk": begun["pk"]}
                    )
                )
                self.assertEqual(cancelled.status_code, 200)
                self.assertEqual(cancelled.data["status"], "cancelled")
                self.client.force_login(self.caller)
                self.assertEqual(self.complete().status_code, 400)
