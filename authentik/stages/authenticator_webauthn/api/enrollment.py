"""Privileged WebAuthn ceremonies; authentik remains the credential verifier."""

from datetime import timedelta
from hashlib import sha256
from json import dumps, loads
from typing import Any, cast
from uuid import UUID

from django.db import IntegrityError, transaction
from django.db.models import QuerySet
from django.shortcuts import get_object_or_404
from django.utils.timezone import now
from django.utils.translation import gettext_lazy as _
from django_filters.rest_framework import DjangoFilterBackend
from drf_spectacular.utils import extend_schema
from rest_framework import mixins
from rest_framework.decorators import action
from rest_framework.fields import CharField, ChoiceField, DateTimeField
from rest_framework.permissions import BasePermission, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.serializers import PrimaryKeyRelatedField, Serializer, ValidationError
from rest_framework.viewsets import GenericViewSet
from structlog.stdlib import get_logger
from webauthn.helpers.base64url_to_bytes import base64url_to_bytes
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url
from webauthn.helpers.options_to_json_dict import options_to_json_dict

from authentik.api.validation import validate
from authentik.core.api.utils import JSONDictField, ModelSerializer
from authentik.core.models import User
from authentik.events.models import Event, EventAction
from authentik.lib.config import CONFIG
from authentik.lib.utils.time import timedelta_from_string
from authentik.rbac.filters import ObjectFilter
from authentik.rbac.permissions import HasPermission
from authentik.stages.authenticator_webauthn.models import (
    AuthenticatorWebAuthnStage,
    WebAuthnEnrollment,
)
from authentik.stages.authenticator_webauthn.registration import (
    VerifiedRegistrationData,
    create_device,
    generate_options,
    verify_registration,
)
from authentik.stages.authenticator_webauthn.utils import (
    get_expected_origins,
    get_origin,
    get_rp_id,
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
        if value.status == WebAuthnEnrollment.Status.PENDING and value.enrollment_expires <= now():
            return WebAuthnEnrollment.Status.EXPIRED
        return str(value.status)


class WebAuthnEnrollmentSerializer(ModelSerializer):
    """Public status; enrollment options are returned only by begin."""

    expires = DateTimeField(source="enrollment_expires", read_only=True)
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


class WebAuthnEnrollmentViewSet(
    mixins.ListModelMixin, mixins.RetrieveModelMixin, GenericViewSet[WebAuthnEnrollment]
):
    """Prepare, verify and cancel enrollment on behalf of an existing user.

    Model permissions and native endpoint checks govern operations and target
    visibility. Only the initiating caller or a superuser can complete an attempt.
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
        qs = WebAuthnEnrollment.objects.all().order_by("-created")
        if self.action == "complete" and not self.request.user.is_superuser:
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
        if user.is_superuser and not self.request.user.is_superuser:
            self.permission_denied(
                self.request,
                message=_("Only superusers can enroll authenticators for superusers."),
            )
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

    def _audit(self, action: EventAction, record: WebAuthnEnrollment) -> None:
        Event.new(
            action,
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
        origin, rp_id = get_origin(request), get_rp_id(request)
        key_digest = sha256(body.validated_data["idempotency_key"].encode()).hexdigest()
        with transaction.atomic():
            # Lock stage before issuer: stage deletion also locks stage before
            # updating enrollments. Do not introduce a user -> stage lock cycle.
            stage = get_object_or_404(
                AuthenticatorWebAuthnStage.objects.select_for_update(), pk=stage.pk
            )
            # Serialize simultaneous idempotent starts by this connector.
            User.objects.select_for_update().get(pk=request.user.pk)
            record = (
                WebAuthnEnrollment.objects.including_expired()
                .filter(requested_by=caller, idempotency_key_digest=key_digest)
                .first()
            )
            if record:
                if record.is_expired:
                    raise ValidationError(
                        {
                            "detail": "This request has expired; use a new idempotency key.",
                            "code": "enrollment_expired",
                        }
                    )
                record = get_object_or_404(self.filter_queryset(self.get_queryset()), pk=record.pk)
                if (
                    record.user_id != user.pk
                    or record.stage_id != stage.pk
                    or record.origin != origin
                    or record.rp_id != rp_id
                ):
                    raise ValidationError(
                        {
                            "detail": "Idempotency key was used with different parameters.",
                            "code": "idempotency_conflict",
                        }
                    )
                if (
                    record.status != WebAuthnEnrollment.Status.PENDING
                    or record.enrollment_expires <= now()
                ):
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
                options = generate_options(
                    stage, user, rp_id, cast(Any, request).brand.branding_title
                )
                try:
                    duration = timedelta_from_string(stage.delegated_enrollment_timeout)
                    if duration <= timedelta(0):
                        raise ValueError("Nonpositive enrollment duration")
                    expires = now() + duration
                except (ValueError, OverflowError) as exc:
                    raise ValidationError(
                        {
                            "detail": (
                                "Configure a positive, representable "
                                "enrollment duration on the stage."
                            ),
                            "code": "enrollment_policy_invalid",
                        }
                    ) from exc
                retention_days = enrollment_integer_setting(
                    "webauthn_enrollment.retention_days", 30, minimum=0
                )
                try:
                    cleanup_after = expires + timedelta(days=retention_days)
                except OverflowError as exc:
                    raise ValidationError(
                        "AUTHENTIK_WEBAUTHN_ENROLLMENT__RETENTION_DAYS produces an "
                        "unrepresentable cleanup date. Configure a shorter retention period."
                    ) from exc
                record = WebAuthnEnrollment.objects.create(
                    user=user,
                    stage=stage,
                    requested_by=caller,
                    idempotency_key_digest=key_digest,
                    challenge=bytes_to_base64url(options.challenge),
                    registration_options=options_to_json_dict(options),
                    rp_id=rp_id,
                    origin=origin,
                    enrollment_expires=expires,
                    expires=cleanup_after,
                )
                self._audit(EventAction.WEBAUTHN_ENROLLMENT_STARTED, record)
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
            if record.enrollment_expires <= now():
                record.status = WebAuthnEnrollment.Status.EXPIRED
                record.save(update_fields=["status"])
                self._audit(EventAction.WEBAUTHN_ENROLLMENT_EXPIRED, record)
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
            if record.rp_id != get_rp_id(request) or record.origin != get_origin(request):
                raise ValidationError(
                    {
                        "detail": "Complete enrollment through the domain where it began.",
                        "code": "enrollment_context_mismatch",
                    }
                )
            verified = self._verify(record, response, stage)
            try:
                with transaction.atomic():
                    device = create_device(user, record.rp_id, verified)
            except IntegrityError as exc:
                raise ValidationError(
                    {"detail": "Credential ID already exists.", "code": "credential_exists"}
                ) from exc
            record.status = WebAuthnEnrollment.Status.COMPLETED
            record.completed, record.device = now(), device
            record.response_digest = digest
            record.save(update_fields=["status", "completed", "device", "response_digest"])
            self._audit(EventAction.WEBAUTHN_ENROLLMENT_COMPLETED, record)
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
                self._audit(EventAction.WEBAUTHN_ENROLLMENT_CANCELLED, record)
        return Response(self.get_serializer(record).data)

    def _verify(
        self,
        record: WebAuthnEnrollment,
        response: dict[str, Any],
        stage: AuthenticatorWebAuthnStage,
    ) -> VerifiedRegistrationData:
        try:
            client_data = loads(base64url_to_bytes(response["response"]["clientDataJSON"]))
            # The delegated endpoint accepts same-origin creation ceremonies only.
            if (
                not isinstance(client_data, dict)
                or client_data.get("crossOrigin", False) is not False
                or "topOrigin" in client_data
            ):
                raise ValueError("Unsupported credential creation context")
        except ValueError, TypeError, KeyError:
            raise ValidationError(
                {"detail": "Registration failed.", "code": "credential_invalid"}
            ) from None
        try:
            return verify_registration(
                stage,
                response,
                challenge=base64url_to_bytes(record.challenge),
                rp_id=record.rp_id,
                origins=get_expected_origins(self.request, stage.additional_accepted_origins),
                issued_uv_required=record.registration_options["authenticatorSelection"][
                    "userVerification"
                ]
                == "required",
                issued_algorithms=[
                    option["alg"] for option in record.registration_options["pubKeyCredParams"]
                ],
            )
        except ValidationError as exc:
            code = (
                "credential_exists"
                if exc.get_codes() == ["credential_exists"]
                else "credential_invalid"
            )
            raise ValidationError({"detail": str(exc.detail[0]), "code": code}) from None
