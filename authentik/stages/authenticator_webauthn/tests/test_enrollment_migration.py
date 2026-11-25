"""The delegated enrollment migration preserves existing credentials."""

from django.db import connection
from django.db.migrations.executor import MigrationExecutor
from django.test import TransactionTestCase
from django.urls import reverse
from rest_framework.test import APIClient
from webauthn.helpers.base64url_to_bytes import base64url_to_bytes
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
from webauthn.helpers.cose import COSEAlgorithmIdentifier

from authentik.core.tests.utils import create_test_admin_user, create_test_flow, create_test_user
from authentik.flows.planner import PLAN_CONTEXT_PENDING_USER, FlowPlan
from authentik.flows.views.executor import SESSION_KEY_PLAN
from authentik.stages.authenticator_validate.models import AuthenticatorValidateStage
from authentik.stages.authenticator_validate.stage import PLAN_CONTEXT_DEVICE_CHALLENGES
from authentik.stages.authenticator_webauthn.models import WebAuthnDevice
from authentik.stages.authenticator_webauthn.stage import PLAN_CONTEXT_WEBAUTHN_CHALLENGE
from authentik.stages.authenticator_webauthn.tests.credentials import SoftwareCredential
from authentik.stages.user_login.models import UserLoginStage


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
            old_stage = executor.loader.project_state(previous).apps.get_model(
                app, "AuthenticatorWebAuthnStage"
            )
            stage = old_stage.objects.create(
                name="Existing stage", user_verification="required", max_attempts=3
            )
            executor = MigrationExecutor(connection)
            executor.migrate(current)
            upgraded = executor.loader.project_state(current).apps.get_model(app, "WebAuthnDevice")
            new_stage = (
                executor.loader.project_state(current)
                .apps.get_model(app, "AuthenticatorWebAuthnStage")
                .objects.get(pk=stage.pk)
            )
            self.assertEqual(new_stage.user_verification, "required")
            self.assertEqual(new_stage.max_attempts, 3)
            self.assertEqual(new_stage.delegated_enrollment_timeout, "minutes=5")
            retained = upgraded.objects.get(pk=device.pk)
            for field, expected in values.items():
                self.assertEqual(getattr(retained, field), expected)
            self.assert_existing_login(user, retained.pk, credential)
            self.assert_new_enrollment(user, stage.pk)
        finally:
            MigrationExecutor(connection).migrate(latest)

    def assert_existing_login(self, user, device_pk, credential):
        challenge = b"migration-authentication-challenge"
        # Use the native flow executor and login stage, as in WebAuthn validation tests.
        client = APIClient()
        flow = create_test_flow()
        validate = AuthenticatorValidateStage.objects.create(
            name="Existing credential validation",
            device_classes=["webauthn"],
            not_configured_action="deny",
            webauthn_user_verification="required",
        )
        plan = FlowPlan(flow_pk=flow.pk.hex)
        plan.append_stage(validate)
        plan.append_stage(UserLoginStage.objects.create(name="Upgraded login"))
        plan.context[PLAN_CONTEXT_PENDING_USER] = user
        plan.context[PLAN_CONTEXT_DEVICE_CHALLENGES] = [
            {
                "device_class": "webauthn",
                "device_uid": device_pk,
                "challenge": {},
                "last_used": None,
            }
        ]
        plan.context[PLAN_CONTEXT_WEBAUTHN_CHALLENGE] = challenge
        session = client.session
        session[SESSION_KEY_PLAN] = plan
        session.save()
        endpoint = reverse("authentik_api:flow-executor", kwargs={"flow_slug": flow.slug})
        response = client.post(
            endpoint,
            {"webauthn": credential.assertion_response(challenge)},
            format="json",
            secure=True,
        )
        self.assertEqual(response.status_code, 302)
        client.get(endpoint, secure=True)
        me = client.get(reverse("authentik_api:user-me"), secure=True)
        self.assertEqual(me.status_code, 200)
        self.assertEqual(me.data["user"]["pk"], user.pk)
        self.assertEqual(WebAuthnDevice.objects.get(pk=device_pk).sign_count, 43)

    def assert_new_enrollment(self, user, stage_pk):
        # The upgraded schema also supports a new delegated ceremony.
        admin = APIClient()
        admin.force_login(create_test_admin_user())
        begun = admin.post(
            reverse("authentik_api:admin-webauthnenrollment-begin"),
            {
                "user": user.pk,
                "stage": str(stage_pk),
                "idempotency_key": "after-upgrade",
            },
            format="json",
            secure=True,
        )
        self.assertEqual(begun.status_code, 201)
        new_key = SoftwareCredential(
            rp_id="testserver",
            origin="https://testserver",
            alg=COSEAlgorithmIdentifier.ECDSA_SHA_256,
        )
        completed = admin.post(
            reverse(
                "authentik_api:admin-webauthnenrollment-complete",
                kwargs={"pk": begun.data["pk"]},
            ),
            {
                "response": new_key.registration_response(
                    base64url_to_bytes(begun.data["registration"]["challenge"])
                ),
            },
            format="json",
            secure=True,
        )
        self.assertEqual(completed.status_code, 200)
        self.assertEqual(completed.data["status"], "completed")
        self.assertEqual(WebAuthnDevice.objects.get(pk=completed.data["device"]).user_id, user.pk)
