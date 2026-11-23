"""The delegated enrollment migration preserves existing credentials."""

from datetime import timedelta

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from django.utils.timezone import now
from webauthn.authentication.verify_authentication_response import verify_authentication_response
from webauthn.helpers.base64url_to_bytes import base64url_to_bytes
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
from webauthn.helpers.cose import COSEAlgorithmIdentifier

from authentik.core.tests.utils import create_test_user
from authentik.stages.authenticator_webauthn.tests.credentials import SoftwareCredential


class TestEnrollmentMigration(TransactionTestCase):
    def test_existing_credential_is_preserved(self):
        app = "authentik_stages_authenticator_webauthn"
        previous = [(app, "0019_authenticatorwebauthnstage_additional_accepted_origins")]
        current = [(app, "0020_webauthnenrollment")]
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        executor.migrate(previous)
        try:
            user = create_test_user()
            old = executor.loader.project_state(previous).apps.get_model(app, "WebAuthnDevice")
            credential = SoftwareCredential(
                rp_id="testserver",
                origin="https://testserver",
                alg=COSEAlgorithmIdentifier.ECDSA_SHA_256,
            )
            credential.sign_count = 42
            values = {
                "user_id": user.pk,
                "name": "Existing key",
                "credential_id": bytes_to_base64url(credential.credential_id),
                "public_key": bytes_to_base64url(credential.cose_public_key),
                "sign_count": 42,
                "rp_id": "testserver",
                "confirmed": True,
            }
            device = old.objects.create(**values)
            executor = MigrationExecutor(connection)
            executor.migrate(current)
            upgraded = executor.loader.project_state(current).apps.get_model(app, "WebAuthnDevice")
            retained = upgraded.objects.get(pk=device.pk)
            for field, expected in values.items():
                self.assertEqual(getattr(retained, field), expected)
            challenge = b"migration-authentication-challenge"
            verified = verify_authentication_response(
                credential=credential.assertion_response(challenge),
                expected_challenge=challenge,
                expected_rp_id=retained.rp_id,
                expected_origin=credential.origin,
                credential_public_key=base64url_to_bytes(retained.public_key),
                credential_current_sign_count=retained.sign_count,
                require_user_verification=True,
            )
            self.assertEqual(verified.credential_id, base64url_to_bytes(retained.credential_id))
            self.assertEqual(verified.new_sign_count, 43)
        finally:
            MigrationExecutor(connection).migrate(latest)

    def test_existing_enrollment_deadlines_and_results_survive_retention_migration(self):
        app = "authentik_stages_authenticator_webauthn"
        previous = [(app, "0020_webauthnenrollment")]
        current = [(app, "0021_enrollment_record_lifecycle")]
        executor = MigrationExecutor(connection)
        latest = executor.loader.graph.leaf_nodes()
        executor.migrate(previous)
        try:
            user = create_test_user()
            old_apps = executor.loader.project_state(previous).apps
            old = old_apps.get_model(app, "WebAuthnEnrollment")
            device = old_apps.get_model(app, "WebAuthnDevice").objects.create(
                user_id=user.pk,
                name="Existing key",
                credential_id="existing-credential",
                public_key="existing-public-key",
                rp_id="testserver",
                sign_count=42,
            )
            deadline = now() + timedelta(minutes=5)
            identifiers = {}
            for status in ("pending", "completed", "cancelled", "expired"):
                identifiers[status] = old.objects.create(
                    user_id=user.pk,
                    requested_by_id=user.pk,
                    challenge="existing-challenge",
                    registration_options={"challenge": "existing-challenge"},
                    rp_id="testserver",
                    origin="https://testserver",
                    idempotency_key_digest=status,
                    status=status,
                    expires=deadline,
                    device_id=device.pk if status == "completed" else None,
                    response_digest="existing-response" if status == "completed" else "",
                ).pk
            executor = MigrationExecutor(connection)
            executor.migrate(current)
            upgraded_apps = executor.loader.project_state(current).apps
            upgraded = upgraded_apps.get_model(app, "WebAuthnEnrollment")
            for status, pk in identifiers.items():
                record = upgraded.objects.get(pk=pk)
                self.assertEqual(record.enrollment_expires, deadline)
                self.assertEqual(record.expires, deadline + timedelta(days=30))
                self.assertTrue(record.expiring)
                self.assertEqual(record.status, status)
                self.assertEqual(record.requested_by_id, user.pk)
                self.assertEqual(record.challenge, "existing-challenge")
                if status == "completed":
                    self.assertEqual(record.device_id, device.pk)
                    self.assertEqual(record.response_digest, "existing-response")
            retained_device = upgraded_apps.get_model(app, "WebAuthnDevice").objects.get(
                pk=device.pk
            )
            self.assertEqual(retained_device.credential_id, "existing-credential")
            self.assertEqual(retained_device.public_key, "existing-public-key")
            self.assertEqual(retained_device.sign_count, 42)
            executor = MigrationExecutor(connection)
            executor.migrate(previous)
            restored = executor.loader.project_state(previous).apps.get_model(
                app, "WebAuthnEnrollment"
            )
            for pk in identifiers.values():
                self.assertEqual(restored.objects.get(pk=pk).expires, deadline)
        finally:
            MigrationExecutor(connection).migrate(latest)
