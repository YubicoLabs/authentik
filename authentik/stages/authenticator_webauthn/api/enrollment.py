"""Privileged WebAuthn ceremonies; authentik remains the credential verifier."""

from datetime import timedelta
from hashlib import sha256
from json import dumps, loads
from typing import Any, cast
from urllib.parse import urlsplit
from uuid import UUID

from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509 import load_der_x509_certificate
from django.db import IntegrityError, transaction
from django.db.models import QuerySet
from django.shortcuts import get_object_or_404
from django.utils.timezone import now
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema
from rest_framework import mixins
from rest_framework.decorators import action
from rest_framework.fields import CharField, ChoiceField
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import PrimaryKeyRelatedField, Serializer, ValidationError
from rest_framework.viewsets import GenericViewSet
from structlog.stdlib import get_logger
from webauthn.helpers.base64url_to_bytes import base64url_to_bytes
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.options_to_json_dict import options_to_json_dict
from webauthn.helpers.parse_attestation_object import parse_attestation_object
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
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

from authentik.api.validation import validate
from authentik.core.api.utils import JSONDictField, ModelSerializer
from authentik.core.models import User
from authentik.crypto.models import fingerprint_sha256
from authentik.events.models import Event
from authentik.lib.config import CONFIG
from authentik.rbac.filters import ObjectFilter
from authentik.rbac.permissions import HasPermission
from authentik.stages.authenticator_webauthn.algorithms import supported_pub_key_algs
from authentik.stages.authenticator_webauthn.models import (
    UNKNOWN_DEVICE_TYPE_AAGUID,
    AuthenticatorWebAuthnStage,
    WebAuthnDevice,
    WebAuthnDeviceType,
    WebAuthnEnrollment,
)
from authentik.stages.authenticator_webauthn.stage import (
    get_authenticator_attachment,
)

APP = "authentik_stages_authenticator_webauthn"
LOGGER = get_logger()


def enrollment_integer_setting(setting: str, default: int, *, minimum: int) -> int:
    """Accept whole-number settings without silently truncating configured values."""
    value = CONFIG.get(setting, default)
    environment_name = "AUTHENTIK_" + setting.upper().replace(".", "__")
    bounds = f"at least {minimum}"
    message = f"Set {environment_name} to a whole number {bounds}."
    if isinstance(value, bool) or not str(value).isascii() or not str(value).isdigit():
        raise ValidationError(message)
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValidationError(message) from exc
    if parsed < minimum:
        raise ValidationError(message)
    return parsed


class EnrollmentStatusField(ChoiceField):
    """Serialize effective expiry before native field rules are applied."""

    def to_representation(self, value: WebAuthnEnrollment) -> str:
        if value.status == WebAuthnEnrollment.Status.PENDING and value.expires <= now():
            return WebAuthnEnrollment.Status.EXPIRED
        return str(value.status)


class WebAuthnEnrollmentSerializer(ModelSerializer):
    """Public status; enrollment options are returned only by begin."""

    status = EnrollmentStatusField(
        source="*", choices=WebAuthnEnrollment.Status.choices, read_only=True
    )

    class Meta:
        model = WebAuthnEnrollment
        fields = [
            "pk",
            "user",
            "stage",
            "rp_id",
            "origin",
            "status",
            "expires",
            "created",
            "completed",
            "device",
        ]
        read_only_fields = fields


class WebAuthnEnrollmentBeginSerializer(Serializer[dict[str, Any]]):
    user = PrimaryKeyRelatedField(queryset=User.objects.all())
    stage = PrimaryKeyRelatedField(queryset=AuthenticatorWebAuthnStage.objects.all())
    idempotency_key = CharField(trim_whitespace=False)


class WebAuthnEnrollmentOptionsSerializer(WebAuthnEnrollmentSerializer):
    registration = JSONDictField(read_only=True)

    class Meta(WebAuthnEnrollmentSerializer.Meta):
        fields = WebAuthnEnrollmentSerializer.Meta.fields + ["registration"]
        read_only_fields = fields


class WebAuthnEnrollmentCompleteSerializer(Serializer[dict[str, Any]]):
    response = JSONDictField()


def enrollment_origin() -> tuple[str, str]:
    """Trust deployment configuration, never the connector's Host header."""
    origin = CONFIG.get("webauthn_enrollment.origin", "")
    message = "Set AUTHENTIK_WEBAUTHN_ENROLLMENT__ORIGIN to a valid trusted origin."
    try:
        parsed = urlsplit(origin)
        # urlsplit defers port validation until this property is accessed.
        _ = parsed.port
    except (TypeError, ValueError) as exc:
        raise ValidationError(message) from exc
    if (
        not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
        or not (
            parsed.scheme == "https" or (parsed.scheme == "http" and parsed.hostname == "localhost")
        )
    ):
        raise ValidationError(message)
    return origin, parsed.hostname


class WebAuthnEnrollmentViewSet(
    mixins.ListModelMixin, mixins.RetrieveModelMixin, GenericViewSet[WebAuthnEnrollment]
):
    """Prepare, verify and cancel enrollment on behalf of an existing user.

    Model permissions and native endpoint checks govern operations and target
    visibility. Only the initiating caller or a superuser can manage an attempt.
    No raw credential-create or transaction-update endpoint exists.
    """

    queryset = WebAuthnEnrollment.objects.all()
    serializer_class = WebAuthnEnrollmentSerializer
    filter_backends = [ObjectFilter, DjangoFilterBackend]
    filterset_fields = ["device", "user"]

    def get_permissions(self) -> list[BasePermission]:
        permissions = [f"{APP}.view_webauthnenrollment"]
        if self.action == "begin":
            permissions += [f"{APP}.add_webauthnenrollment"]
        elif self.action in {"complete", "cancel"}:
            permissions += [f"{APP}.change_webauthnenrollment"]
        return [IsAuthenticated(), HasPermission(*permissions)()]

    def get_queryset(self) -> QuerySet[WebAuthnEnrollment]:
        if getattr(self, "swagger_fake_view", False):
            return self.queryset.none()
        qs = super().get_queryset().order_by("-created")
        if not self.request.user.is_superuser:
            qs = qs.filter(requested_by=cast(User, self.request.user))
        return qs

    def _get_locked_enrollment(self, pk: UUID | str | None) -> WebAuthnEnrollment:
        queryset = self.filter_queryset(self.get_queryset()).select_for_update()
        record = get_object_or_404(queryset, pk=pk)
        self.check_object_permissions(self.request, record)
        return record

    def _authorize_target(self, user: User, stage: AuthenticatorWebAuthnStage | None) -> None:
        if not user.is_active:
            raise ValidationError("Target user is inactive.")
        if not (
            self.request.user.has_perm("authentik_core.enroll_user_webauthn", user)
            or self.request.user.has_perm("authentik_core.enroll_user_webauthn")
        ):
            self.permission_denied(self.request)
        objects = [("core/users:list", User.objects.filter(pk=user.pk))]
        if stage is not None:
            objects.append(
                (
                    "stages/authenticator/webauthn:list",
                    AuthenticatorWebAuthnStage.objects.filter(pk=stage.pk),
                )
            )
        for endpoint, queryset in objects:
            if not ObjectFilter.visible_in_list(self.request, queryset, endpoint).exists():
                self.permission_denied(self.request)

    def _audit(self, operation: str, record: WebAuthnEnrollment) -> None:
        Event.new(
            f"webauthn_enrollment_{operation}",
            transaction_id=str(record.pk),
            target_user_id=record.user_id,
            device_id=record.device_id,
        ).from_http(self.request._request)

    @extend_schema(
        request=WebAuthnEnrollmentBeginSerializer,
        responses={201: WebAuthnEnrollmentOptionsSerializer},
    )
    @action(detail=False, methods=["POST"])
    @validate(WebAuthnEnrollmentBeginSerializer)  # type: ignore[untyped-decorator]
    def begin(self, request: Request, *, body: WebAuthnEnrollmentBeginSerializer) -> Response:
        """Return creation options bound to the user, RP and a one-time challenge."""
        user, stage = body.validated_data["user"], body.validated_data["stage"]
        caller = cast(User, request.user)  # IsAuthenticated runs before this action.
        self._authorize_target(user, stage)
        origin, rp_id = enrollment_origin()
        key_digest = sha256(body.validated_data["idempotency_key"].encode()).hexdigest()
        with transaction.atomic():
            # Lock stage before issuer: stage deletion also locks stage before
            # updating enrollments. Do not introduce a user -> stage lock cycle.
            stage = get_object_or_404(
                AuthenticatorWebAuthnStage.objects.select_for_update(), pk=stage.pk
            )
            # Serialize simultaneous idempotent starts by this connector.
            User.objects.select_for_update().get(pk=request.user.pk)
            record = WebAuthnEnrollment.objects.filter(
                requested_by=caller, idempotency_key_digest=key_digest
            ).first()
            if record:
                record = get_object_or_404(self.filter_queryset(self.get_queryset()), pk=record.pk)
                if (
                    record.user_id != user.pk
                    or record.stage_id != stage.pk
                    or record.origin != origin
                ):
                    raise ValidationError(
                        {
                            "detail": "Idempotency key was used with different parameters.",
                            "code": "idempotency_conflict",
                        }
                    )
                if record.status != WebAuthnEnrollment.Status.PENDING or record.expires <= now():
                    raise ValidationError(
                        {
                            "detail": (
                                "This request is no longer pending; use a new idempotency key."
                            ),
                            "code": (
                                "enrollment_expired"
                                if record.status == WebAuthnEnrollment.Status.PENDING
                                else f"enrollment_{record.status}"
                            ),
                        }
                    )
            else:
                options = generate_registration_options(
                    rp_id=rp_id,
                    rp_name=cast(Any, request).brand.branding_title,
                    user_id=user.uid.encode(),
                    user_name=user.username,
                    user_display_name=user.name,
                    authenticator_selection=AuthenticatorSelectionCriteria(
                        resident_key=ResidentKeyRequirement(str(stage.resident_key_requirement)),
                        user_verification=UserVerificationRequirement(str(stage.user_verification)),
                        authenticator_attachment=get_authenticator_attachment(stage),
                    ),
                    attestation=AttestationConveyancePreference.DIRECT,
                    exclude_credentials=[
                        PublicKeyCredentialDescriptor(id=base64url_to_bytes(value))
                        for value in WebAuthnDevice.objects.filter(
                            user=user, rp_id=rp_id, confirmed=True
                        ).values_list("credential_id", flat=True)
                    ],
                    hints=[PublicKeyCredentialHint(h) for h in stage.hints] or None,
                    supported_pub_key_algs=supported_pub_key_algs(),
                )
                ttl = enrollment_integer_setting(
                    "webauthn_enrollment.ttl_seconds",
                    300,
                    minimum=1,
                )
                try:
                    expires = now() + timedelta(seconds=ttl)
                except OverflowError as exc:
                    raise ValidationError(
                        "AUTHENTIK_WEBAUTHN_ENROLLMENT__TTL_SECONDS produces an "
                        "unrepresentable expiration date. Configure a shorter lifetime."
                    ) from exc
                record = WebAuthnEnrollment.objects.create(
                    user=user,
                    stage=stage,
                    requested_by=caller,
                    idempotency_key_digest=key_digest,
                    challenge=bytes_to_base64url(options.challenge),
                    registration_options=options_to_json_dict(options),
                    allowed_aaguids=[
                        str(value)
                        for value in stage.device_type_restrictions.values_list("aaguid", flat=True)
                    ],
                    rp_id=rp_id,
                    origin=origin,
                    expires=expires,
                )
                self._audit("started", record)
        data = self.get_serializer(record).data
        data["registration"] = record.registration_options
        return Response(data, status=201)

    @extend_schema(
        request=WebAuthnEnrollmentCompleteSerializer,
        responses={200: WebAuthnEnrollmentSerializer},
    )
    @action(detail=True, methods=["POST"])
    @validate(WebAuthnEnrollmentCompleteSerializer)  # type: ignore[untyped-decorator]
    def complete(
        self,
        request: Request,
        pk: UUID | str | None = None,
        *,
        body: WebAuthnEnrollmentCompleteSerializer,
    ) -> Response:
        """Verify the attestation and atomically create a real WebAuthnDevice."""
        response = body.validated_data["response"]
        digest = sha256(
            dumps(
                response,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest()
        with transaction.atomic():
            record = self._get_locked_enrollment(pk)
            user = User.objects.select_for_update().get(pk=record.user_id)
            # Stage deletion must update this locked enrollment before deleting
            # the stage. Do not lock stage here: that would invert deletion's order.
            stage = (
                AuthenticatorWebAuthnStage.objects.filter(pk=record.stage_id).first()
                if record.stage_id is not None
                else None
            )
            self._authorize_target(user, stage)
            if record.status == WebAuthnEnrollment.Status.COMPLETED:
                if record.response_digest == digest and record.device_id:
                    return Response(self.get_serializer(record).data)
                raise ValidationError(
                    {
                        "detail": "Enrollment is already completed.",
                        "code": (
                            "enrollment_completed" if record.device_id else "credential_revoked"
                        ),
                    }
                )
            if record.status != WebAuthnEnrollment.Status.PENDING:
                raise ValidationError(
                    {
                        "detail": "Enrollment is not pending.",
                        "code": f"enrollment_{record.status}",
                    }
                )
            if record.expires <= now():
                record.status = WebAuthnEnrollment.Status.EXPIRED
                record.save(update_fields=["status"])
                self._audit("expired", record)
                # Normal return commits expiry; raising would roll it back.
                return Response(
                    {"detail": "Enrollment has expired.", "code": "enrollment_expired"},
                    status=400,
                )
            if stage is None:
                raise ValidationError(
                    {
                        "detail": (
                            "The enrollment stage was deleted. "
                            "Start a new enrollment with an available stage."
                        ),
                        "code": "enrollment_policy_unavailable",
                    }
                )
            verified, certificate, fingerprint = self._verify(record, response)
            device_type = WebAuthnDeviceType.objects.filter(aaguid=verified.aaguid).first()
            try:
                with transaction.atomic():
                    device = WebAuthnDevice.objects.create(
                        name="Enrolled authenticator",
                        user=user,
                        confirmed=True,
                        public_key=bytes_to_base64url(verified.credential_public_key),
                        credential_id=bytes_to_base64url(verified.credential_id),
                        sign_count=verified.sign_count,
                        rp_id=record.rp_id,
                        device_type=device_type,
                        aaguid=verified.aaguid,
                        attestation_certificate_pem=certificate,
                        attestation_certificate_fingerprint=fingerprint,
                    )
            except IntegrityError as exc:
                raise ValidationError(
                    {"detail": "Credential ID already exists.", "code": "credential_exists"}
                ) from exc
            record.status = WebAuthnEnrollment.Status.COMPLETED
            record.completed, record.device = now(), device
            record.response_digest = digest
            record.save(update_fields=["status", "completed", "device", "response_digest"])
            self._audit("completed", record)
        return Response(self.get_serializer(record).data)

    @extend_schema(request=None, responses={200: WebAuthnEnrollmentSerializer})
    @action(detail=True, methods=["POST"])
    def cancel(self, request: Request, pk: UUID | str | None = None) -> Response:
        """Cancel pending enrollment; completed credentials use device revocation."""
        with transaction.atomic():
            record = self._get_locked_enrollment(pk)
            if record.status == WebAuthnEnrollment.Status.COMPLETED:
                raise ValidationError(
                    {
                        "detail": "Enrollment completed; revoke the credential instead.",
                        "code": "enrollment_completed",
                    }
                )
            if record.status == WebAuthnEnrollment.Status.PENDING:
                record.status = WebAuthnEnrollment.Status.CANCELLED
                record.save(update_fields=["status"])
                self._audit("cancelled", record)
        return Response(self.get_serializer(record).data)

    def _verify(
        self, record: WebAuthnEnrollment, response: dict[str, Any]
    ) -> tuple[VerifiedRegistration, str | None, str | None]:
        try:
            client_data = loads(base64url_to_bytes(response["response"]["clientDataJSON"]))
            # This endpoint supports same-origin ceremonies only. The verifier
            # validates origin, but does not enforce the embedding context.
            if (
                not isinstance(client_data, dict)
                or client_data.get("crossOrigin", False) is not False
                or "topOrigin" in client_data
            ):
                raise ValueError("Unsupported credential creation context")
            offered_algorithms = {
                option["alg"] for option in record.registration_options["pubKeyCredParams"]
            }
            allowed_algorithms = [
                algorithm
                for algorithm in supported_pub_key_algs()
                if algorithm in offered_algorithms
            ]
            if not allowed_algorithms:
                raise ValueError("No offered algorithm is currently supported")
            verified = verify_registration_response(
                credential=response,
                expected_challenge=base64url_to_bytes(record.challenge),
                expected_rp_id=record.rp_id,
                expected_origin=record.origin,
                require_user_verification=record.registration_options["authenticatorSelection"][
                    "userVerification"
                ]
                == "required",
                supported_pub_key_algs=allowed_algorithms,
            )
        except (WebAuthnException, ValueError, TypeError, KeyError) as exc:
            LOGGER.warning(
                "WebAuthn enrollment verification failed",
                error_type=type(exc).__name__,
                enrollment_id=str(record.pk),
            )
            raise ValidationError(
                {"detail": "Registration failed.", "code": "credential_invalid"}
            ) from exc
        allowed = set(record.allowed_aaguids)
        aaguid = str(verified.aaguid)
        unknown_allowed = (
            UNKNOWN_DEVICE_TYPE_AAGUID in allowed
            and not WebAuthnDeviceType.objects.filter(aaguid=aaguid).exists()
        )
        if allowed and aaguid not in allowed and not unknown_allowed:
            raise ValidationError({"detail": "Invalid device type.", "code": "credential_invalid"})
        if WebAuthnDevice.objects.filter(
            credential_id=bytes_to_base64url(verified.credential_id)
        ).exists():
            raise ValidationError(
                {"detail": "Credential ID already exists.", "code": "credential_exists"}
            )
        certificate = fingerprint = None
        attestation = parse_attestation_object(verified.attestation_object)
        if attestation.att_stmt.x5c:
            try:
                cert = load_der_x509_certificate(attestation.att_stmt.x5c[0])
            except ValueError as exc:
                # Match the interactive stage: certificate storage is optional after verification.
                LOGGER.warning(
                    "Failed to parse enrollment attestation certificate",
                    error_type=type(exc).__name__,
                    enrollment_id=str(record.pk),
                )
            else:
                certificate = cert.public_bytes(Encoding.PEM).decode()
                fingerprint = fingerprint_sha256(cert)
        return verified, certificate, fingerprint
