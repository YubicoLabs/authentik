"""The delegated enrollment migration preserves existing credentials."""

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from webauthn.authentication.verify_authentication_response import verify_authentication_response
from webauthn.helpers.base64url_to_bytes import base64url_to_bytes
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url

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
            credential = SoftwareCredential(rp_id="testserver", origin="https://testserver")
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
