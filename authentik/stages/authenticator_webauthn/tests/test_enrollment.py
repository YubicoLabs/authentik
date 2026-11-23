"""Cryptographic integration tests for delegated WebAuthn enrollment.

These tests intentionally use a software ES256 authenticator instead of mocking
the WebAuthn verifier or device persistence. They exercise the packed
self-attestation shape a FIDO2 authenticator returns to a connector.
"""

from datetime import datetime, timedelta
from hashlib import sha256
from json import dumps
from os import urandom
from unittest.mock import patch
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDSA,
    SECP256R1,
    generate_private_key,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID
from django.urls import reverse
from django.utils.timezone import now
from fido2 import cbor
from fido2.cose import ES256
from fido2.webauthn import AttestationObject, AttestedCredentialData, AuthenticatorData
from rest_framework.test import APITestCase
from webauthn.helpers.base64url_to_bytes import base64url_to_bytes
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
from webauthn.helpers.cose import COSEAlgorithmIdentifier

from authentik.core.models import UserTypes
from authentik.core.tests.utils import create_test_admin_user, create_test_user
from authentik.lib.config import CONFIG, UNSET
from authentik.lib.generators import generate_id
from authentik.stages.authenticator_webauthn.models import (
    UNKNOWN_DEVICE_TYPE_AAGUID,
    AuthenticatorWebAuthnStage,
    WebAuthnDevice,
    WebAuthnDeviceType,
    WebAuthnEnrollment,
)


class SoftwareES256Credential:
    """Synthetic ES256 registration-response builder for verifier tests."""

    def __init__(self, rp_id: str, origin: str, aaguid=UNKNOWN_DEVICE_TYPE_AAGUID):
        self.rp_id = rp_id
        self.origin = origin
        self.aaguid = aaguid
        self.credential_id = urandom(32)
        self.private_key = generate_private_key(SECP256R1())

    def registration_response(
        self,
        challenge: bytes,
        *,
        user_verified: bool = True,
        user_present: bool = True,
        valid_signature: bool = True,
        client_context: dict | None = None,
    ) -> dict:
        client_data = dumps(
            {
                "type": "webauthn.create",
                "challenge": bytes_to_base64url(challenge),
                "origin": self.origin,
                **({"crossOrigin": False} if client_context is None else client_context),
            }
        ).encode()
        credential_data = AttestedCredentialData.create(
            UUID(self.aaguid).bytes,
            self.credential_id,
            ES256.from_cryptography_key(self.private_key.public_key()),
        )
        flags = AuthenticatorData.FLAG.AT
        if user_present:
            flags |= AuthenticatorData.FLAG.UP
        if user_verified:
            flags |= AuthenticatorData.FLAG.UV
        authenticator_data = AuthenticatorData.create(
            sha256(self.rp_id.encode()).digest(), flags, 0, credential_data
        )
        signature = self.private_key.sign(
            bytes(authenticator_data) + sha256(client_data).digest(), ECDSA(SHA256())
        )
        if not valid_signature:
            signature = signature[:-1] + bytes([signature[-1] ^ 1])
        attestation = AttestationObject.create(
            "packed", authenticator_data, {"alg": -7, "sig": signature}
        )
        return {
            "id": bytes_to_base64url(self.credential_id),
            "rawId": bytes_to_base64url(self.credential_id),
            "type": "public-key",
            "registrationClientExtensions": {},
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "attestationObject": bytes_to_base64url(bytes(attestation)),
            },
        }


class TestWebAuthnEnrollment(APITestCase):
    """The connector may transport a ceremony, but never bypass its verification."""

    def setUp(self):
        self.previous_ttl = CONFIG.get("webauthn_enrollment.ttl_seconds", default=UNSET)
        CONFIG.delete("webauthn_enrollment.ttl_seconds")
        self.previous_origin = CONFIG.get("webauthn_enrollment.origin", default=UNSET)
        CONFIG.set("webauthn_enrollment.origin", "https://testserver")
        self.admin = create_test_admin_user()
        self.user = create_test_user()
        self.stage = AuthenticatorWebAuthnStage.objects.create(name=generate_id())
        self.client.force_login(self.admin)

    def tearDown(self):
        if self.previous_ttl is UNSET:
            CONFIG.delete("webauthn_enrollment.ttl_seconds")
        else:
            CONFIG.set("webauthn_enrollment.ttl_seconds", self.previous_ttl)
        if self.previous_origin is UNSET:
            CONFIG.delete("webauthn_enrollment.origin")
        else:
            CONFIG.set("webauthn_enrollment.origin", self.previous_origin)

    def begin(self, *, user=None, stage=None, key="request-1", **extra):
        return self.client.post(
            reverse("authentik_api:admin-webauthnenrollment-begin"),
            {
                "user": str((user or self.user).pk),
                "stage": str((stage or self.stage).pk),
                "idempotency_key": key,
            },
            content_type="application/json",
            **extra,
        )

    def test_valid_response_is_not_rejected_by_a_feature_specific_size_cap(self):
        """Valid extension data must not trigger a feature-specific size restriction."""
        enrollment = self.begin()
        _, response = self.credential_response(enrollment)
        response["clientExtensionResults"] = {"example": "a" * (128 * 1024)}
        completed = self.complete(enrollment.data["pk"], response)
        self.assertEqual(completed.status_code, 200)
        self.assertEqual(completed.data["status"], "completed")

    def credential_response(self, begin_response, **kwargs):
        credential = SoftwareES256Credential(
            begin_response.data["registration"]["rp"]["id"], begin_response.data["origin"]
        )
        challenge = base64url_to_bytes(begin_response.data["registration"]["challenge"])
        return credential, credential.registration_response(challenge, **kwargs)

    def test_long_idempotency_key_retries_without_a_storage_index_error(self):
        key = "issuance-request-" * 1024
        first = self.begin(key=key)
        self.assertEqual(first.status_code, 201)
        self.assertEqual(self.begin(key=key).data, first.data)
        second = self.begin(key=key + "other")
        self.assertEqual(second.status_code, 201)
        self.assertNotEqual(second.data["pk"], first.data["pk"])

    def test_valid_origin_longer_than_default_url_field_storage(self):
        origin = "https://" + ".".join(["a" * 60] * 3 + ["example", "com"]) + ":8443"
        self.assertGreater(len(origin), 200)
        CONFIG.set("webauthn_enrollment.origin", origin)
        begun = self.begin()
        self.assertEqual(begun.status_code, 201)
        self.assertEqual(begun.data["origin"], origin)

    def test_no_implicit_pending_capacity_policy(self):
        first = self.begin(key="pending-0")
        self.assertEqual(first.status_code, 201)
        for index in range(1, 101):
            self.assertEqual(self.begin(key=f"pending-{index}").status_code, 201)
        self.assertEqual(self.begin(key="pending-0").data, first.data)

    def test_completion_audit_records_actor_and_binding_without_credential_payload(self):
        begun = self.begin()
        _, response = self.credential_response(begun)
        completed = self.complete(begun.data["pk"], response)
        self.assertEqual(completed.status_code, 200)
        self.assertEqual(self.complete(begun.data["pk"], response).status_code, 200)
        events = self.client.get(
            reverse("authentik_api:event-list"),
            {"action": "custom_webauthn_enrollment_completed"},
        )
        self.assertEqual(events.status_code, 200)
        matching = [
            event
            for event in events.data["results"]
            if event["context"].get("transaction_id") == str(begun.data["pk"])
        ]
        self.assertEqual(len(matching), 1)
        event = matching[0]
        self.assertEqual(event["user"]["pk"], self.admin.pk)
        self.assertEqual(event["context"]["target_user_id"], self.user.pk)
        self.assertEqual(event["context"]["device_id"], completed.data["device"])
        serialized = dumps(event)
        self.assertNotIn(response["response"]["clientDataJSON"], serialized)
        self.assertNotIn(response["response"]["attestationObject"], serialized)

    def complete(self, enrollment_pk, credential_response, **extra):
        return self.client.post(
            reverse(
                "authentik_api:admin-webauthnenrollment-complete",
                kwargs={"pk": enrollment_pk},
            ),
            {"response": credential_response, **extra},
            content_type="application/json",
        )

    def test_cross_origin_context_is_rejected_without_consuming_attempt(self):
        for context in (
            {"crossOrigin": True},
            {"crossOrigin": False, "topOrigin": "https://other.example"},
            {"crossOrigin": "false"},
        ):
            with self.subTest(context=context):
                begun = self.begin(key=dumps(context))
                credential, response = self.credential_response(begun, client_context=context)
                rejected = self.complete(begun.data["pk"], response)
                self.assertEqual(rejected.status_code, 400)
                self.assertEqual(rejected.data["code"], "credential_invalid")
                corrected = credential.registration_response(
                    base64url_to_bytes(begun.data["registration"]["challenge"])
                )
                self.assertEqual(self.complete(begun.data["pk"], corrected).status_code, 200)

    def test_completion_rejects_an_algorithm_not_offered_at_begin(self):
        # Model a deployment broadening its supported algorithms between requests.
        with patch(
            "authentik.stages.authenticator_webauthn.api.enrollment.supported_pub_key_algs",
            return_value=[COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256],
        ):
            begun = self.begin()
        self.assertEqual(
            begun.data["registration"]["pubKeyCredParams"], [{"type": "public-key", "alg": -257}]
        )
        _, response = self.credential_response(begun)
        rejected = self.complete(begun.data["pk"], response)
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(rejected.data["code"], "credential_invalid")

    def test_missing_user_presence_is_rejected_without_consuming_attempt(self):
        begun = self.begin()
        credential, response = self.credential_response(begun, user_present=False)
        rejected = self.complete(begun.data["pk"], response)
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(rejected.data["code"], "credential_invalid")
        corrected = credential.registration_response(
            base64url_to_bytes(begun.data["registration"]["challenge"])
        )
        self.assertEqual(self.complete(begun.data["pk"], corrected).status_code, 200)

    def test_completion_requires_current_algorithm_support(self):
        begun = self.begin()
        _, response = self.credential_response(begun)
        for algorithms in ([], [COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256]):
            with (
                self.subTest(algorithms=algorithms),
                patch(
                    "authentik.stages.authenticator_webauthn.api.enrollment.supported_pub_key_algs",
                    return_value=algorithms,
                ),
            ):
                rejected = self.complete(begun.data["pk"], response)
                self.assertEqual(rejected.status_code, 400)
                self.assertEqual(rejected.data["code"], "credential_invalid")
        self.assertEqual(self.complete(begun.data["pk"], response).status_code, 200)

    def test_omitted_cross_origin_is_accepted_and_replayable(self):
        begun = self.begin()
        _, response = self.credential_response(begun, client_context={})
        completed = self.complete(begun.data["pk"], response)
        self.assertEqual(completed.status_code, 200)
        replay = self.complete(begun.data["pk"], response)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.data, completed.data)

    def test_registration_and_replay_need_only_the_standard_credential_response(self):
        begun = self.begin()
        self.assertNotIn("external_id", begun.data)
        _, response = self.credential_response(begun)
        completed = self.complete(begun.data["pk"], response)
        self.assertEqual(completed.status_code, 200)
        self.assertNotIn("external_id", completed.data)
        replay = self.complete(begun.data["pk"], response)
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.data["device"], completed.data["device"])
        self.assertNotIn("external_id", replay.data)

    def test_default_and_configured_lifetime(self):
        for configured, seconds in (
            (None, 300),
            (1, 1),
            (59, 59),
            (3600, 3600),
            (2592001, 2592001),
        ):
            with self.subTest(seconds=seconds):
                if configured is not None:
                    CONFIG.set("webauthn_enrollment.ttl_seconds", configured)
                before = now()
                begun = self.begin(key=f"ttl-{seconds}")
                after = now()
                self.assertEqual(begun.status_code, 201)
                record = WebAuthnEnrollment.objects.get(pk=begun.data["pk"])
                self.assertGreaterEqual(
                    record.enrollment_expires, before + timedelta(seconds=seconds)
                )
                self.assertLessEqual(record.enrollment_expires, after + timedelta(seconds=seconds))

    def test_inspection_reports_expiry_without_a_completion_attempt(self):
        """Status polling must not advertise an elapsed challenge as usable."""
        clock = "authentik.stages.authenticator_webauthn.api.enrollment.now"
        with patch(clock, return_value=datetime.fromisoformat("2026-11-10T12:00:00Z")):
            begun = self.begin()
        detail_url = reverse(
            "authentik_api:admin-webauthnenrollment-detail",
            kwargs={"pk": begun.data["pk"]},
        )
        list_url = reverse("authentik_api:admin-webauthnenrollment-list")
        for instant, expected in (
            ("2026-11-10T12:04:59.999999Z", "pending"),
            ("2026-11-10T12:05:00Z", "expired"),
            ("2026-11-10T12:05:01Z", "expired"),
        ):
            with (
                self.subTest(instant=instant),
                patch(clock, return_value=datetime.fromisoformat(instant)),
            ):
                detail = self.client.get(detail_url)
                self.assertEqual(detail.status_code, 200)
                self.assertEqual(detail.data["status"], expected)
                self.assertEqual(detail.data["expires"], begun.data["expires"])
                self.assertIsNone(detail.data["device"])
                listed = self.client.get(list_url)
                self.assertEqual(listed.status_code, 200)
                record = next(r for r in listed.data["results"] if r["pk"] == begun.data["pk"])
                self.assertEqual(record["status"], expected)

    def test_inspection_preserves_terminal_results_after_deadline(self):
        """Expiry applies to pending attempts, not accepted or cancelled results."""
        clock = "authentik.stages.authenticator_webauthn.api.enrollment.now"
        with patch(clock, return_value=datetime.fromisoformat("2026-11-10T12:00:00Z")):
            completed = self.begin(key="completed")
            _, response = self.credential_response(completed)
            accepted = self.complete(completed.data["pk"], response)
            self.assertEqual(accepted.status_code, 200)
            cancelled = self.begin(key="cancelled")
            cancelled_result = self.client.post(
                reverse(
                    "authentik_api:admin-webauthnenrollment-cancel",
                    kwargs={"pk": cancelled.data["pk"]},
                )
            )
            self.assertEqual(cancelled_result.status_code, 200)
        with patch(clock, return_value=datetime.fromisoformat("2026-11-10T12:05:00Z")):
            listed = self.client.get(reverse("authentik_api:admin-webauthnenrollment-list"))
            self.assertEqual(listed.status_code, 200)
            for original in (accepted, cancelled_result):
                inspected = self.client.get(
                    reverse(
                        "authentik_api:admin-webauthnenrollment-detail",
                        kwargs={"pk": original.data["pk"]},
                    )
                )
                self.assertEqual(inspected.status_code, 200)
                self.assertEqual(inspected.data, original.data)
                record = next(r for r in listed.data["results"] if r["pk"] == original.data["pk"])
                self.assertEqual(record, original.data)
            replay = self.complete(completed.data["pk"], response)
            self.assertEqual(replay.status_code, 200)
            self.assertEqual(replay.data, accepted.data)

    def test_invalid_lifetime_rejects_enrollment(self):
        for value in (0, -1, 10**30, "invalid"):
            with self.subTest(value=value):
                CONFIG.set("webauthn_enrollment.ttl_seconds", value)
                begun = self.begin(key=f"invalid-{value}")
                self.assertEqual(begun.status_code, 400)
                self.assertFalse(WebAuthnEnrollment.objects.exists())

    def test_config_change_does_not_extend_existing_ceremony(self):
        begun = self.begin()
        CONFIG.set("webauthn_enrollment.ttl_seconds", 3600)
        retried = self.begin()
        self.assertEqual(retried.status_code, 201)
        self.assertEqual(retried.data["pk"], begun.data["pk"])
        self.assertEqual(retried.data["expires"], begun.data["expires"])
        self.assertEqual(retried.data["registration"], begun.data["registration"])

    def test_non_integer_lifetime_is_actionable_and_does_not_issue_an_attempt(self):
        setting = "webauthn_enrollment.ttl_seconds"
        for index, value in enumerate(
            (300.5, 300.0, True, None, "３００", "300_000", " 300 ", "+300")
        ):
            with self.subTest(value=value):
                CONFIG.set(setting, value)
                rejected = self.begin(key=f"invalid-lifetime-{index}")
                self.assertEqual(rejected.status_code, 400)
                self.assertIn("AUTHENTIK_WEBAUTHN_ENROLLMENT__TTL_SECONDS", str(rejected.data))
                listed = self.client.get(reverse("authentik_api:admin-webauthnenrollment-list"))
                self.assertEqual(listed.status_code, 200)
                self.assertEqual(listed.data["results"], [])
        CONFIG.set(setting, "300")
        recovered = self.begin(key="invalid-lifetime-0")
        self.assertEqual(recovered.status_code, 201)

    def test_complete_accepts_valid_packed_es256_attestation_and_persists_device(self):
        begun = self.begin()
        self.assertEqual(begun.status_code, 201)
        self.assertEqual(begun.data["registration"]["rp"]["id"], "testserver")

        credential, attestation = self.credential_response(begun)
        completed = self.complete(begun.data["pk"], attestation)

        self.assertEqual(completed.status_code, 200)
        self.assertEqual(completed.data["status"], WebAuthnEnrollment.Status.COMPLETED)
        device = WebAuthnDevice.objects.get(
            credential_id=bytes_to_base64url(credential.credential_id)
        )
        self.assertEqual(device.user, self.user)
        self.assertEqual(device.rp_id, "testserver")
        self.assertEqual(
            device.public_key,
            bytes_to_base64url(
                cbor.encode(ES256.from_cryptography_key(credential.private_key.public_key()))
            ),
        )

    def test_begin_requires_a_configured_origin_and_ignores_connector_host_header(self):
        CONFIG.delete("webauthn_enrollment.origin")
        self.assertEqual(self.begin().status_code, 400)

        CONFIG.set("webauthn_enrollment.origin", "https://testserver")
        begun = self.begin(key="fixed-origin", HTTP_HOST="localhost:9000")
        self.assertEqual(begun.status_code, 201)
        self.assertEqual(begun.data["origin"], "https://testserver")
        self.assertEqual(begun.data["rp_id"], "testserver")
        self.assertEqual(begun.data["registration"]["rp"]["id"], "testserver")

    def test_malformed_origin_configuration_is_rejected_and_correctable(self):
        for origin in ("https://[broken", "https://testserver:invalid", "https://testserver:65536"):
            with self.subTest(origin=origin):
                CONFIG.set("webauthn_enrollment.origin", origin)
                self.assertEqual(self.begin().status_code, 400)
        CONFIG.set("webauthn_enrollment.origin", "https://testserver:8443")
        begun = self.begin()
        self.assertEqual(begun.status_code, 201)
        self.assertEqual(begun.data["origin"], "https://testserver:8443")
        self.assertEqual(begun.data["rp_id"], "testserver")

    def test_certificate_backed_attestation_checks_signature_and_allows_corrected_retry(self):
        begun = self.begin()
        _, response = self.credential_response(begun)
        attestation = AttestationObject(
            base64url_to_bytes(response["response"]["attestationObject"])
        )
        attestation_key = generate_private_key(SECP256R1())
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Enrollment tests"),
                x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Authenticator Attestation"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic test authenticator"),
            ]
        )
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(attestation_key.public_key())
            .serial_number(1)
            .not_valid_before(now() - timedelta(days=1))
            .not_valid_after(now() + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(attestation_key, SHA256())
        )
        client_data = base64url_to_bytes(response["response"]["clientDataJSON"])
        signature = attestation_key.sign(
            bytes(attestation.auth_data) + sha256(client_data).digest(), ECDSA(SHA256())
        )
        for valid in (False, True):
            with self.subTest(valid_signature=valid):
                statement = {
                    "alg": -7,
                    "sig": signature if valid else signature[:-1] + bytes([signature[-1] ^ 1]),
                    "x5c": [certificate.public_bytes(Encoding.DER)],
                }
                response["response"]["attestationObject"] = bytes_to_base64url(
                    bytes(AttestationObject.create("packed", attestation.auth_data, statement))
                )
                result = self.complete(begun.data["pk"], response)
                self.assertEqual(result.status_code, 200 if valid else 400)
        self.assertEqual(result.data["status"], "completed")
        # This exercises certificate-backed verification, not manufacturer trust:
        # the API supplies no configured attestation trust roots to the verifier.
        self.assertEqual(self.complete(begun.data["pk"], response).data, result.data)

    def test_complete_rejects_invalid_packed_attestation_signature(self):
        begun = self.begin()
        _, attestation = self.credential_response(begun, valid_signature=False)

        response = self.complete(begun.data["pk"], attestation)

        self.assertEqual(response.status_code, 400)
        self.assertFalse(WebAuthnDevice.objects.filter(user=self.user).exists())

    def test_complete_rejects_challenge_origin_and_rp_id_substitution(self):
        cases = (
            (
                "challenge",
                lambda begun: SoftwareES256Credential(
                    begun.data["registration"]["rp"]["id"], begun.data["origin"]
                ),
                b"wrong",
            ),
            (
                "origin",
                lambda begun: SoftwareES256Credential(
                    begun.data["registration"]["rp"]["id"], "https://evil.example"
                ),
                None,
            ),
            (
                "rp_id",
                lambda begun: SoftwareES256Credential("evil.example", begun.data["origin"]),
                None,
            ),
        )
        for label, make_credential, challenge_override in cases:
            with self.subTest(label=label):
                begun = self.begin(key=f"request-{label}")
                credential = make_credential(begun)
                challenge = challenge_override or base64url_to_bytes(
                    begun.data["registration"]["challenge"]
                )
                response = self.complete(
                    begun.data["pk"], credential.registration_response(challenge)
                )
                self.assertEqual(response.status_code, 400)
        self.assertFalse(WebAuthnDevice.objects.filter(user=self.user).exists())

    def test_interactive_origin_allowlist_does_not_widen_delegated_origin(self):
        self.stage.additional_accepted_origins = ["https://native-client.example"]
        self.stage.save(update_fields=["additional_accepted_origins"])
        begun = self.begin()
        credential = SoftwareES256Credential(
            begun.data["registration"]["rp"]["id"], "https://native-client.example"
        )
        challenge = base64url_to_bytes(begun.data["registration"]["challenge"])
        self.assertEqual(
            self.complete(
                begun.data["pk"], credential.registration_response(challenge)
            ).status_code,
            400,
        )
        self.assertFalse(WebAuthnDevice.objects.filter(user=self.user).exists())
        _, response = self.credential_response(begun)
        self.assertEqual(self.complete(begun.data["pk"], response).status_code, 200)

    def test_complete_requires_uv_when_stage_requires_it(self):
        self.stage.user_verification = "required"
        self.stage.save(update_fields=["user_verification"])
        begun = self.begin()
        _, attestation = self.credential_response(begun, user_verified=False)

        response = self.complete(begun.data["pk"], attestation)

        self.assertEqual(response.status_code, 400)
        self.assertFalse(WebAuthnDevice.objects.filter(user=self.user).exists())

    def test_complete_delivery_retry_is_idempotent_but_changed_response_is_rejected(self):
        first = self.begin(key="first")
        credential, first_attestation = self.credential_response(first)
        first_completion = self.complete(first.data["pk"], first_attestation)
        self.assertEqual(first_completion.status_code, 200)

        retry = self.complete(first.data["pk"], first_attestation)
        self.assertEqual(retry.status_code, 200)
        self.assertEqual(retry.data["device"], first_completion.data["device"])
        self.assertEqual(WebAuthnDevice.objects.filter(user=self.user).count(), 1)

        changed = {**first_attestation, "clientExtensionResults": {"example": True}}
        self.assertEqual(self.complete(first.data["pk"], changed).status_code, 400)

        second = self.begin(key="second")
        second_challenge = base64url_to_bytes(second.data["registration"]["challenge"])
        duplicate = credential.registration_response(second_challenge)
        self.assertEqual(self.complete(second.data["pk"], duplicate).status_code, 400)
        self.assertEqual(WebAuthnDevice.objects.filter(user=self.user).count(), 1)

    def test_completion_uses_the_begin_policy_snapshot(self):
        self.stage.user_verification = "discouraged"
        self.stage.save(update_fields=["user_verification"])
        begun = self.begin(key="policy-snapshot")

        # Tightening the mutable stage after delivery starts must not invalidate its issued
        # registration request. The immutable request snapshot says UV was discouraged.
        self.stage.user_verification = "required"
        self.stage.save(update_fields=["user_verification"])
        _, attestation = self.credential_response(begun, user_verified=False)
        self.assertEqual(self.complete(begun.data["pk"], attestation).status_code, 200)

    def test_aaguid_allowlist_snapshot_accepts_credential_allowed_at_begin(self):
        allowed_aaguid = "11111111-1111-1111-1111-111111111111"
        replacement_aaguid = "22222222-2222-2222-2222-222222222222"
        allowed_type = WebAuthnDeviceType.objects.create(
            aaguid=allowed_aaguid, description="Allowed at begin"
        )
        replacement_type = WebAuthnDeviceType.objects.create(
            aaguid=replacement_aaguid, description="Allowed after begin"
        )
        self.stage.device_type_restrictions.set([allowed_type])
        begun = self.begin(key="aaguid-accept-snapshot")
        record = WebAuthnEnrollment.objects.get(pk=begun.data["pk"])
        self.assertEqual(record.allowed_aaguids, [allowed_aaguid])

        # Changing the stage later cannot change this ceremony's allowlist.
        self.stage.device_type_restrictions.set([replacement_type])
        credential = SoftwareES256Credential(
            begun.data["registration"]["rp"]["id"], begun.data["origin"], allowed_aaguid
        )
        challenge = base64url_to_bytes(begun.data["registration"]["challenge"])
        self.assertEqual(
            self.complete(
                begun.data["pk"], credential.registration_response(challenge)
            ).status_code,
            200,
        )

    def test_aaguid_allowlist_snapshot_rejects_credential_disallowed_at_begin(self):
        allowed_aaguid = "33333333-3333-3333-3333-333333333333"
        later_aaguid = "44444444-4444-4444-4444-444444444444"
        allowed_type = WebAuthnDeviceType.objects.create(
            aaguid=allowed_aaguid, description="Only allowed at begin"
        )
        self.stage.device_type_restrictions.set([allowed_type])
        begun = self.begin(key="aaguid-reject-snapshot")
        record = WebAuthnEnrollment.objects.get(pk=begun.data["pk"])
        self.assertEqual(record.allowed_aaguids, [allowed_aaguid])

        # Relaxing the mutable stage later must not permit a different authenticator.
        self.stage.device_type_restrictions.clear()
        credential = SoftwareES256Credential(
            begun.data["registration"]["rp"]["id"], begun.data["origin"], later_aaguid
        )
        challenge = base64url_to_bytes(begun.data["registration"]["challenge"])
        self.assertEqual(
            self.complete(
                begun.data["pk"], credential.registration_response(challenge)
            ).status_code,
            400,
        )
        self.assertFalse(WebAuthnDevice.objects.filter(user=self.user).exists())

    def test_expired_or_cancelled_ceremony_cannot_persist_a_device(self):
        expired = self.begin(key="expired")
        enrollment = WebAuthnEnrollment.objects.get(pk=expired.data["pk"])
        enrollment.enrollment_expires = now() - timedelta(seconds=1)
        enrollment.save(update_fields=["enrollment_expires"])
        _, expired_attestation = self.credential_response(expired)
        self.assertEqual(
            self.complete(expired.data["pk"], expired_attestation).status_code,
            400,
        )
        enrollment.refresh_from_db()
        self.assertEqual(enrollment.status, WebAuthnEnrollment.Status.EXPIRED)
        self.assertIsNone(enrollment.device_id)

        cancelled = self.begin(key="cancelled")
        cancel = self.client.post(
            reverse(
                "authentik_api:admin-webauthnenrollment-cancel",
                kwargs={"pk": cancelled.data["pk"]},
            )
        )
        self.assertEqual(cancel.status_code, 200)
        _, cancelled_attestation = self.credential_response(cancelled)
        self.assertEqual(
            self.complete(
                cancelled.data["pk"],
                cancelled_attestation,
            ).status_code,
            400,
        )
        self.assertFalse(WebAuthnDevice.objects.filter(user=self.user).exists())
        detail = self.client.get(
            reverse(
                "authentik_api:admin-webauthnenrollment-detail", kwargs={"pk": cancelled.data["pk"]}
            )
        )
        self.assertEqual(detail.data["status"], "cancelled")

    def test_begin_requires_privilege_and_idempotency_key_cannot_change_request_scope(self):
        self.client.force_login(create_test_user())
        self.assertEqual(self.begin().status_code, 403)

        self.client.force_login(self.admin)
        initial = self.begin(key="stable-key")
        self.assertEqual(initial.status_code, 201)
        retry = self.begin(key="stable-key")
        self.assertEqual(retry.status_code, 201)
        self.assertEqual(retry.data["pk"], initial.data["pk"])

        other_stage = AuthenticatorWebAuthnStage.objects.create(name=generate_id())
        mismatch = self.begin(stage=other_stage, key="stable-key")
        self.assertEqual(mismatch.status_code, 400)

    def test_begin_retry_cannot_rebind_target_user(self):
        """An idempotency key cannot redirect an existing attempt to another account."""
        original = self.begin(key="bound-user")
        self.assertEqual(original.status_code, 201)
        other_user = create_test_user()
        rejected = self.begin(user=other_user, key="bound-user")
        self.assertEqual(rejected.status_code, 400)
        replay = self.begin(key="bound-user")
        self.assertEqual(replay.status_code, 201)
        self.assertEqual(replay.data, original.data)
        listed = self.client.get(reverse("authentik_api:admin-webauthnenrollment-list"))
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.data["pagination"]["count"], 1)
        self.assertEqual(listed.data["results"][0]["pk"], original.data["pk"])
        self.assertEqual(listed.data["results"][0]["user"], self.user.pk)

    def test_begin_issues_binary_challenge_as_base64url_and_retry_preserves_it(self):
        first = self.begin(key="challenge-first")
        self.assertEqual(first.status_code, 201)
        encoded = first.json()["registration"]["challenge"]
        self.assertRegex(encoded, r"^[A-Za-z0-9_-]+$")
        # W3C recommends at least 16 bytes, not 16 encoded characters:
        # https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges
        self.assertGreaterEqual(len(base64url_to_bytes(encoded)), 16)
        retry = self.begin(key="challenge-first")
        self.assertEqual(retry.status_code, 201)
        self.assertEqual(retry.json()["registration"]["challenge"], encoded)
        second = self.begin(key="challenge-second")
        self.assertEqual(second.status_code, 201)
        self.assertNotEqual(second.json()["registration"]["challenge"], encoded)
        # A valid response to the second challenge cannot complete the first attempt.
        _, second_response = self.credential_response(second)
        self.assertEqual(self.complete(first.data["pk"], second_response).status_code, 400)
        _, first_response = self.credential_response(first)
        self.assertEqual(self.complete(first.data["pk"], first_response).status_code, 200)

    def test_cross_user_responses_cannot_swap_enrollment_ownership(self):
        """A valid signature for another user's challenge cannot enroll this user."""
        other_user = create_test_user()
        first = self.begin(key="first-user")
        second = self.begin(user=other_user, key="second-user")
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 201)
        self.assertNotEqual(
            first.data["registration"]["challenge"], second.data["registration"]["challenge"]
        )
        self.assertNotEqual(
            first.data["registration"]["user"]["id"], second.data["registration"]["user"]["id"]
        )
        _, first_response = self.credential_response(first)
        _, second_response = self.credential_response(second)
        self.assertEqual(self.complete(first.data["pk"], second_response).status_code, 400)
        self.assertEqual(self.complete(second.data["pk"], first_response).status_code, 400)
        for begun in (first, second):
            inspected = self.client.get(
                reverse(
                    "authentik_api:admin-webauthnenrollment-detail",
                    kwargs={"pk": begun.data["pk"]},
                )
            )
            self.assertEqual(inspected.status_code, 200)
            self.assertEqual(inspected.data["status"], "pending")
            self.assertIsNone(inspected.data["device"])
        devices = self.client.get(reverse("authentik_api:admin-webauthndevice-list"))
        self.assertEqual(devices.status_code, 200)
        self.assertEqual(devices.data["pagination"]["count"], 0)

        # Invalid substitution must not consume either valid attempt. Complete in reverse order.
        completed_ids = set()
        for begun, response, owner in (
            (second, second_response, other_user),
            (first, first_response, self.user),
        ):
            completed = self.complete(begun.data["pk"], response)
            self.assertEqual(completed.status_code, 200)
            self.assertEqual(completed.data["status"], "completed")
            device = self.client.get(
                reverse(
                    "authentik_api:admin-webauthndevice-detail",
                    kwargs={"pk": completed.data["device"]},
                )
            )
            self.assertEqual(device.status_code, 200)
            self.assertEqual(device.data["user"]["pk"], owner.pk)
            completed_ids.add(device.data["pk"])
        self.assertEqual(len(completed_ids), 2)
        devices = self.client.get(reverse("authentik_api:admin-webauthndevice-list"))
        self.assertEqual(devices.status_code, 200)
        self.assertEqual(devices.data["pagination"]["count"], 2)
        self.assertEqual({device["pk"] for device in devices.data["results"]}, completed_ids)

    def test_scoped_service_caller_can_only_manage_its_own_authorized_request(self):
        service_caller = create_test_user(type=UserTypes.SERVICE_ACCOUNT)
        other_caller = create_test_user(type=UserTypes.SERVICE_ACCOUNT)
        for caller in (service_caller, other_caller):
            caller.assign_perms_to_managed_role(
                [
                    "authentik_stages_authenticator_webauthn.add_webauthnenrollment",
                    "authentik_stages_authenticator_webauthn.change_webauthnenrollment",
                    "authentik_stages_authenticator_webauthn.view_webauthnenrollment",
                    "authentik_core.enroll_user_webauthn",
                ]
            )

        self.client.force_login(service_caller)
        # Model permissions alone cannot target a user or stage outside this caller's grants.
        self.assertEqual(self.begin(key="scoped").status_code, 403)
        service_caller.assign_perms_to_managed_role("authentik_core.view_user", self.user)
        self.assertEqual(self.begin(key="scoped").status_code, 403)
        service_caller.assign_perms_to_managed_role(
            "authentik_stages_authenticator_webauthn.view_authenticatorwebauthnstage",
            self.stage,
        )
        begun = self.begin(key="scoped")
        self.assertEqual(begun.status_code, 201)

        # A different, fully model-authorized connector cannot retrieve or complete a request
        # it did not create, even if it is later granted target access.
        other_caller.assign_perms_to_managed_role("authentik_core.view_user", self.user)
        other_caller.assign_perms_to_managed_role(
            "authentik_stages_authenticator_webauthn.view_authenticatorwebauthnstage",
            self.stage,
        )
        self.client.force_login(other_caller)
        detail_url = reverse(
            "authentik_api:admin-webauthnenrollment-detail", kwargs={"pk": begun.data["pk"]}
        )
        self.assertEqual(self.client.get(detail_url).status_code, 404)
        _, attestation = self.credential_response(begun)
        self.assertEqual(self.complete(begun.data["pk"], attestation).status_code, 404)
        cancel_url = reverse(
            "authentik_api:admin-webauthnenrollment-cancel", kwargs={"pk": begun.data["pk"]}
        )
        self.assertEqual(self.client.post(cancel_url).status_code, 404)
        listed = self.client.get(reverse("authentik_api:admin-webauthnenrollment-list"))
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.data["pagination"]["count"], 0)
        self.assertEqual(listed.data["results"], [])

        # Unauthorized operations must not consume or cancel the rightful caller's attempt.
        self.client.force_login(service_caller)
        inspected = self.client.get(detail_url)
        self.assertEqual(inspected.status_code, 200)
        self.assertEqual(inspected.data["status"], "pending")
        self.assertIsNone(inspected.data["device"])
        completed = self.complete(begun.data["pk"], attestation)
        self.assertEqual(completed.status_code, 200)
        self.assertEqual(completed.data["status"], "completed")
        self.assertIsNotNone(completed.data["device"])
