"""Delegated registration uses native stage attachment and hint preferences."""

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.tests.utils import create_test_admin_user, create_test_user
from authentik.lib.config import CONFIG, UNSET
from authentik.lib.generators import generate_id
from authentik.stages.authenticator_webauthn.models import AuthenticatorWebAuthnStage


class TestEnrollmentStagePreferences(APITestCase):
    """Registration options do not silently impose a vendor's hardware preference."""

    def setUp(self):
        self.previous_origin = CONFIG.get("webauthn_enrollment.origin", default=UNSET)
        CONFIG.set("webauthn_enrollment.origin", "https://testserver")
        self.addCleanup(self.restore_origin)
        self.user = create_test_user()
        self.client.force_login(create_test_admin_user())

    def restore_origin(self):
        if self.previous_origin is UNSET:
            CONFIG.delete("webauthn_enrollment.origin")
        else:
            CONFIG.set("webauthn_enrollment.origin", self.previous_origin)

    def options(self, attachment=None, hints=None):
        stage = AuthenticatorWebAuthnStage.objects.create(
            name=generate_id(), authenticator_attachment=attachment, hints=hints or []
        )
        begun = self.client.post(
            reverse("authentik_api:admin-webauthnenrollment-begin"),
            {"user": self.user.pk, "stage": str(stage.pk), "idempotency_key": generate_id()},
            format="json",
        )
        self.assertEqual(begun.status_code, 201, begun.data)
        return begun.data["registration"]

    def test_explicit_platform_attachment_is_supported(self):
        options = self.options(attachment="platform")
        self.assertEqual(options["authenticatorSelection"]["authenticatorAttachment"], "platform")

    def test_explicit_roaming_attachment_is_preserved(self):
        options = self.options(attachment="cross-platform")
        self.assertEqual(
            options["authenticatorSelection"]["authenticatorAttachment"], "cross-platform"
        )

    def test_unset_attachment_and_hints_do_not_force_roaming(self):
        options = self.options()
        self.assertNotIn("authenticatorAttachment", options["authenticatorSelection"])
        self.assertNotIn("hints", options)

    def test_client_device_hint_infers_platform_attachment(self):
        options = self.options(hints=["client-device"])
        self.assertEqual(options["hints"], ["client-device"])
        self.assertEqual(options["authenticatorSelection"]["authenticatorAttachment"], "platform")

    def test_roaming_hints_infer_attachment_and_preserve_preference_order(self):
        for hints in (["security-key"], ["hybrid"], ["hybrid", "security-key"]):
            with self.subTest(hints=hints):
                options = self.options(hints=hints)
                self.assertEqual(options["hints"], hints)
                self.assertEqual(
                    options["authenticatorSelection"]["authenticatorAttachment"], "cross-platform"
                )

    def test_mixed_hints_preserve_order_without_inferring_attachment(self):
        options = self.options(hints=["client-device", "hybrid", "security-key"])
        self.assertEqual(options["hints"], ["client-device", "hybrid", "security-key"])
        self.assertNotIn("authenticatorAttachment", options["authenticatorSelection"])

    def test_explicit_attachment_takes_precedence_over_hint_inference(self):
        for attachment, hints in (
            ("platform", ["security-key"]),
            ("cross-platform", ["client-device"]),
        ):
            with self.subTest(attachment=attachment):
                options = self.options(attachment=attachment, hints=hints)
                self.assertEqual(options["hints"], hints)
                self.assertEqual(
                    options["authenticatorSelection"]["authenticatorAttachment"], attachment
                )
