"""Administrators configure delegated lifetime; each request binds its login domain."""

from django.urls import reverse
from rest_framework.test import APITestCase
from webauthn.helpers.base64url_to_bytes import base64url_to_bytes

from authentik.core.tests.utils import create_test_admin_user, create_test_user
from authentik.lib.config import CONFIG, UNSET
from authentik.lib.generators import generate_id
from authentik.stages.authenticator_webauthn.models import AuthenticatorWebAuthnStage
from authentik.stages.authenticator_webauthn.tests.test_enrollment import SoftwareES256Credential


class TestEnrollmentConfiguration(APITestCase):
    def setUp(self):
        self.client.force_login(create_test_admin_user())
        self.user = create_test_user()
        self.stage = AuthenticatorWebAuthnStage.objects.create(name=generate_id())
        self.stage_url = reverse(
            "authentik_api:authenticatorwebauthnstage-detail", kwargs={"pk": self.stage.pk}
        )
        self.old_origin = CONFIG.get("webauthn_enrollment.origin", default=UNSET)
        CONFIG.set("webauthn_enrollment.origin", "https://old-prototype.example")
        self.addCleanup(self.restore_origin)

    def restore_origin(self):
        if self.old_origin is UNSET:
            CONFIG.delete("webauthn_enrollment.origin")
        else:
            CONFIG.set("webauthn_enrollment.origin", self.old_origin)

    def begin(self, host, key=None):
        return self.client.post(
            reverse("authentik_api:admin-webauthnenrollment-begin"),
            {
                "user": self.user.pk,
                "stage": str(self.stage.pk),
                "idempotency_key": key or generate_id(),
            },
            format="json",
            secure=True,
            HTTP_HOST=host,
        )

    def test_domains_bind_creation_and_pending_completion(self):
        for host in ("login.one.example", "login.two.example"):
            with self.subTest(host=host):
                key = generate_id()
                begun = self.begin(host, key)
                self.assertEqual(begun.status_code, 201)
                self.assertEqual(begun.data["rp_id"], host)
                self.assertEqual(begun.data["origin"], "https://" + host)
                self.assertEqual(self.begin("other.example", key).status_code, 400)
                credential = SoftwareES256Credential(host, "https://" + host)
                body = {
                    "response": credential.registration_response(
                        base64url_to_bytes(begun.data["registration"]["challenge"])
                    )
                }
                url = reverse(
                    "authentik_api:admin-webauthnenrollment-complete",
                    kwargs={"pk": begun.data["pk"]},
                )
                self.assertEqual(
                    self.client.post(
                        url, body, format="json", secure=True, HTTP_HOST="other.example"
                    ).status_code,
                    400,
                )
                self.assertEqual(
                    self.client.post(
                        url, body, format="json", secure=True, HTTP_HOST=host
                    ).status_code,
                    200,
                )

    def test_stage_timeout_is_configurable_and_validated(self):
        self.assertEqual(
            self.client.get(self.stage_url).data["delegated_enrollment_timeout"], "minutes=5"
        )
        for value in ("seconds=0", "minutes=-1", "invalid", "days=999999999"):
            with self.subTest(value=value):
                response = self.client.patch(
                    self.stage_url, {"delegated_enrollment_timeout": value}, format="json"
                )
                self.assertEqual(response.status_code, 400)
                self.assertIn("delegated_enrollment_timeout", response.data)
        updated = self.client.patch(
            self.stage_url, {"delegated_enrollment_timeout": "seconds=0.5"}, format="json"
        )
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.data["delegated_enrollment_timeout"], "seconds=0.5")

    def test_current_additional_origins_control_pending_verification(self):
        self.stage.additional_accepted_origins = ["https://enroller.example"]
        self.stage.save()
        begun = self.begin("login.one.example")
        credential = SoftwareES256Credential("login.one.example", "https://enroller.example")
        body = {
            "response": credential.registration_response(
                base64url_to_bytes(begun.data["registration"]["challenge"])
            )
        }
        url = reverse(
            "authentik_api:admin-webauthnenrollment-complete", kwargs={"pk": begun.data["pk"]}
        )
        self.stage.additional_accepted_origins = []
        self.stage.save()
        self.assertEqual(
            self.client.post(
                url, body, format="json", secure=True, HTTP_HOST="login.one.example"
            ).status_code,
            400,
        )
        self.stage.additional_accepted_origins = ["https://enroller.example"]
        self.stage.save()
        self.assertEqual(
            self.client.post(
                url, body, format="json", secure=True, HTTP_HOST="login.one.example"
            ).status_code,
            200,
        )
