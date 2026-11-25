"""Registration shared by interactive and delegated WebAuthn enrollment."""

from collections.abc import Sequence
from dataclasses import dataclass
from uuid import UUID

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_der_x509_certificate
from rest_framework.serializers import ValidationError
from structlog.stdlib import get_logger
from webauthn.helpers.base64url_to_bytes import base64url_to_bytes
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.parse_attestation_object import parse_attestation_object
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorAttachment,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialCreationOptions,
    PublicKeyCredentialDescriptor,
    PublicKeyCredentialHint,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)
from webauthn.registration.generate_registration_options import generate_registration_options
from webauthn.registration.verify_registration_response import (
    VerifiedRegistration,
    verify_registration_response,
)

from authentik.core.models import User
from authentik.crypto.models import fingerprint_sha256
from authentik.stages.authenticator_webauthn.algorithms import supported_pub_key_algs
from authentik.stages.authenticator_webauthn.models import (
    UNKNOWN_DEVICE_TYPE_AAGUID,
    AuthenticatorWebAuthnStage,
    WebAuthnDevice,
    WebAuthnDeviceType,
)

LOGGER = get_logger()


def get_authenticator_attachment(stage: AuthenticatorWebAuthnStage):
    """Honor explicit attachment, or infer it from hints for older user agents."""
    # Existing stage behavior; hint semantics: https://www.w3.org/TR/webauthn-3/#enum-hints
    if stage.authenticator_attachment:
        return AuthenticatorAttachment(str(stage.authenticator_attachment))
    hints = set(stage.hints)
    if hints and hints <= {"security-key", "hybrid"}:
        return AuthenticatorAttachment.CROSS_PLATFORM
    if hints and hints <= {"client-device"}:
        return AuthenticatorAttachment.PLATFORM
    return None


@dataclass
class VerifiedRegistrationData:
    registration: VerifiedRegistration
    attest_cert: str | None = None
    attest_cert_fingerprint: str | None = None


def generate_options(
    stage: AuthenticatorWebAuthnStage, user: User, rp_id: str, rp_name: str
) -> PublicKeyCredentialCreationOptions:
    """Generate the native stage's creation options for one relying party."""
    # Let the authenticator itself refuse to register a credential it already holds for this
    # user. Only confirmed devices count; an unconfirmed one is not usable and must not block
    # re-enrolling the same authenticator.
    exclude_credentials = [
        PublicKeyCredentialDescriptor(id=base64url_to_bytes(credential_id))
        for credential_id in WebAuthnDevice.objects.filter(user=user, rp_id=rp_id, confirmed=True)
        .order_by("pk")
        .values_list("credential_id", flat=True)
    ]

    registration_options: PublicKeyCredentialCreationOptions = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=user.uid.encode("utf-8"),
        user_name=user.username,
        user_display_name=user.name,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement(str(stage.resident_key_requirement)),
            user_verification=UserVerificationRequirement(str(stage.user_verification)),
            authenticator_attachment=get_authenticator_attachment(stage),
        ),
        attestation=AttestationConveyancePreference.DIRECT,
        exclude_credentials=exclude_credentials,
        hints=[PublicKeyCredentialHint(h) for h in stage.hints] or None,
        supported_pub_key_algs=supported_pub_key_algs(),
    )

    return registration_options


def verify_registration(
    stage: AuthenticatorWebAuthnStage,
    response: dict,
    *,
    challenge: bytes,
    rp_id: str,
    origins: list[str],
    issued_uv_required: bool = False,
    issued_algorithms: Sequence[int] | None = None,
) -> VerifiedRegistrationData:
    """Verify issued proof against the stage's current credential restrictions."""
    algorithms = [
        algorithm
        for algorithm in supported_pub_key_algs()
        if issued_algorithms is None or algorithm in issued_algorithms
    ]
    try:
        if not algorithms:
            raise ValueError("No offered algorithm is currently supported")
        registration = verify_registration_response(
            credential=response,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origins,
            require_user_verification=issued_uv_required or stage.user_verification == "required",
            supported_pub_key_algs=algorithms,
        )
    except (WebAuthnException, ValueError, TypeError, KeyError) as exc:
        LOGGER.warning("registration failed", error_type=type(exc).__name__)
        raise ValidationError(
            "Registration failed. Please contact your administrator.", code="credential_invalid"
        ) from None
    registration_data = VerifiedRegistrationData(registration)

    att_obj = parse_attestation_object(registration.attestation_object)
    if (
        att_obj
        and att_obj.att_stmt
        and att_obj.att_stmt.x5c is not None
        and len(att_obj.att_stmt.x5c) > 0
    ):
        # android-key attestation verifies with OpenSSL, which accepts certificates that
        # cryptography rejects. The registration is valid, so only skip storing the certificate
        try:
            cert = load_der_x509_certificate(att_obj.att_stmt.x5c[0])
        except ValueError as exc:
            LOGGER.warning("failed to parse attestation certificate", error_type=type(exc).__name__)
        else:
            registration_data.attest_cert = cert.public_bytes(
                encoding=Encoding.PEM,
            ).decode("utf-8")
            registration_data.attest_cert_fingerprint = fingerprint_sha256(cert)

    if WebAuthnDevice.objects.filter(
        credential_id=bytes_to_base64url(registration.credential_id)
    ).exists():
        raise ValidationError("Credential ID already exists.", code="credential_exists")

    aaguid = registration.aaguid
    allowed_aaguids = stage.device_type_restrictions.values_list("aaguid", flat=True)
    if allowed_aaguids.exists():
        invalid_error = ValidationError("Invalid device type.", code="device_type_invalid")
        # If there are any restrictions set and we didn't get an aaguid, invalid
        if not aaguid:
            raise invalid_error
        # If one of the restrictions is the "special" unknown device type UUID
        # accept an AAGUID that is not in the device-type catalog
        if (
            UUID(UNKNOWN_DEVICE_TYPE_AAGUID) in allowed_aaguids
            and not WebAuthnDeviceType.objects.filter(aaguid=aaguid).exists()
        ):
            return registration_data
        # Otherwise just check if the given aaguid is in the allowed aaguids
        if UUID(aaguid) not in allowed_aaguids:
            raise invalid_error
    return registration_data


def create_device(user: User, rp_id: str, data: VerifiedRegistrationData) -> WebAuthnDevice:
    """Persist a verified credential with native device-type naming."""
    name = "WebAuthn Device"
    device_type = WebAuthnDeviceType.objects.filter(aaguid=data.registration.aaguid).first()
    if device_type and device_type.description:
        name = device_type.description
    return WebAuthnDevice.objects.create(
        name=name,
        user=user,
        public_key=bytes_to_base64url(data.registration.credential_public_key),
        credential_id=bytes_to_base64url(data.registration.credential_id),
        sign_count=data.registration.sign_count,
        rp_id=rp_id,
        device_type=device_type,
        aaguid=data.registration.aaguid,
        attestation_certificate_pem=data.attest_cert,
        attestation_certificate_fingerprint=data.attest_cert_fingerprint,
    )
