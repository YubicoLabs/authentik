"""Enrollment records are runtime state with explicit caller ownership."""

from datetime import timedelta

from django.test import TestCase
from django.utils.timezone import now

from authentik.blueprints.v1.exporter import Exporter
from authentik.blueprints.v1.importer import Importer
from authentik.core.tasks import clean_expired_models
from authentik.core.tests.utils import create_test_user
from authentik.stages.authenticator_webauthn.models import (
    AuthenticatorWebAuthnStage,
    WebAuthnDevice,
    WebAuthnEnrollment,
)


class TestEnrollmentRecords(TestCase):
    def setUp(self):
        self.user = create_test_user()
        self.caller = create_test_user()
        self.stage = AuthenticatorWebAuthnStage.objects.create(name="enrollment-policy")
        self.enrollment = WebAuthnEnrollment.objects.create(
            user=self.user,
            requested_by=self.caller,
            stage=self.stage,
            challenge="test-challenge",
            rp_id="testserver",
            origin="https://testserver",
            idempotency_key_digest="test-request",
            enrollment_expires=now() + timedelta(minutes=5),
            expires=now() + timedelta(days=30, minutes=5),
        )

    def test_blueprint_export_excludes_enrollment_records(self):
        exported = Exporter().export()
        self.assertNotIn(
            "authentik_stages_authenticator_webauthn.webauthnenrollment",
            [entry.model for entry in exported.entries],
        )

    def test_blueprint_cannot_delete_an_enrollment_record(self):
        importer = Importer.from_string(f"""
version: 1
entries:
  - model: authentik_stages_authenticator_webauthn.webauthnenrollment
    identifiers:
      pk: {self.enrollment.pk}
    state: absent
""")
        importer.validate()
        importer.apply()
        self.assertTrue(WebAuthnEnrollment.objects.filter(pk=self.enrollment.pk).exists())

    def test_blueprint_cannot_configure_an_enrollment_record(self):
        importer = Importer.from_string(f"""
version: 1
entries:
  - model: authentik_stages_authenticator_webauthn.webauthnenrollment
    identifiers:
      pk: {self.enrollment.pk}
    state: present
""")
        self.assertFalse(importer.validate()[0])

    def test_deleting_issuer_preserves_enrollment(self):
        self.caller.delete()
        self.enrollment.refresh_from_db()
        self.assertIsNone(self.enrollment.requested_by)
        self.assertEqual(self.enrollment.user_id, self.user.pk)
        self.assertEqual(self.enrollment.status, WebAuthnEnrollment.Status.PENDING)

    def test_cleanup_removes_expired_records_without_deleting_credentials(self):
        device = WebAuthnDevice.objects.create(
            user=self.user,
            name="Retained credential",
            credential_id="existing-credential",
            public_key="existing-public-key",
            rp_id="testserver",
            confirmed=True,
        )
        expired = WebAuthnEnrollment.objects.create(
            user=self.user,
            requested_by=self.caller,
            stage=self.stage,
            challenge="expired-challenge",
            rp_id="testserver",
            origin="https://testserver",
            idempotency_key_digest="expired-request",
            status=WebAuthnEnrollment.Status.COMPLETED,
            device=device,
            enrollment_expires=now() - timedelta(days=31),
            expires=now() - timedelta(days=1),
        )
        clean_expired_models.send()
        self.assertFalse(
            WebAuthnEnrollment.objects.including_expired().filter(pk=expired.pk).exists()
        )
        self.assertTrue(WebAuthnEnrollment.objects.filter(pk=self.enrollment.pk).exists())
        self.assertTrue(WebAuthnDevice.objects.filter(pk=device.pk).exists())
