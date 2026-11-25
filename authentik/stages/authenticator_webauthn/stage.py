"""WebAuthn stage"""

from django.db import IntegrityError, transaction
from django.http import HttpRequest, HttpResponse
from django.http.request import QueryDict
from django.utils.translation import gettext_lazy as _
from rest_framework.fields import CharField
from rest_framework.serializers import ValidationError
from webauthn.helpers.options_to_json_dict import options_to_json_dict

from authentik.core.api.utils import JSONDictField
from authentik.core.models import User
from authentik.flows.challenge import (
    Challenge,
    ChallengeResponse,
    WithUserInfoChallenge,
)
from authentik.flows.stage import ChallengeStageView
from authentik.stages.authenticator_webauthn.models import (
    AuthenticatorWebAuthnStage,
)
from authentik.stages.authenticator_webauthn.registration import (
    VerifiedRegistrationData,
    create_device,
    generate_options,
    verify_registration,
)
from authentik.stages.authenticator_webauthn.utils import get_expected_origins, get_rp_id

PLAN_CONTEXT_WEBAUTHN_CHALLENGE = "goauthentik.io/stages/authenticator_webauthn/challenge"
PLAN_CONTEXT_WEBAUTHN_POLICY = "goauthentik.io/stages/authenticator_webauthn/policy"
PLAN_CONTEXT_WEBAUTHN_ATTEMPT = "goauthentik.io/stages/authenticator_webauthn/attempt"


class AuthenticatorWebAuthnChallenge(WithUserInfoChallenge):
    """WebAuthn Challenge"""

    registration = JSONDictField()
    component = CharField(default="ak-stage-authenticator-webauthn")


class AuthenticatorWebAuthnChallengeResponse(ChallengeResponse):
    """WebAuthn Challenge response"""

    response = JSONDictField()
    component = CharField(default="ak-stage-authenticator-webauthn")

    request: HttpRequest
    user: User

    def validate_response(self, response: dict) -> VerifiedRegistrationData:
        """Validate webauthn challenge response"""
        challenge = self.stage.executor.plan.context[PLAN_CONTEXT_WEBAUTHN_CHALLENGE]
        stage: AuthenticatorWebAuthnStage = self.stage.executor.current_stage
        # Flow plans can retain a stage instance across requests. Verify current policy.
        stage.refresh_from_db()

        issued = self.stage.executor.plan.context.get(PLAN_CONTEXT_WEBAUTHN_POLICY, {})
        try:
            return verify_registration(
                stage,
                response,
                challenge=challenge,
                rp_id=get_rp_id(self.request),
                origins=get_expected_origins(self.request, stage.additional_accepted_origins),
                issued_uv_required=issued.get("uv_required", False),
                issued_algorithms=issued.get("algorithms"),
            )
        except ValidationError as exc:
            if exc.get_codes() == ["device_type_invalid"]:
                raise ValidationError(
                    _("Invalid device type. Contact your {brand} administrator for help.").format(
                        brand=self.request.brand.branding_title
                    )
                ) from None
            raise ValidationError([str(detail) for detail in exc.detail]) from None


class AuthenticatorWebAuthnStageView(ChallengeStageView):
    """WebAuthn stage"""

    response_class = AuthenticatorWebAuthnChallengeResponse

    def get_challenge(self, *args, **kwargs) -> Challenge:
        stage: AuthenticatorWebAuthnStage = self.executor.current_stage
        self.executor.plan.context.setdefault(PLAN_CONTEXT_WEBAUTHN_ATTEMPT, 0)
        # clear flow variables prior to starting a new registration
        self.executor.plan.context.pop(PLAN_CONTEXT_WEBAUTHN_CHALLENGE, None)
        user = self.get_pending_user()

        registration_options = generate_options(
            stage, user, get_rp_id(self.request), self.request.brand.branding_title
        )
        self.executor.plan.context[PLAN_CONTEXT_WEBAUTHN_POLICY] = {
            "uv_required": stage.user_verification == "required",
            "algorithms": [option.alg for option in registration_options.pub_key_cred_params],
        }
        self.executor.plan.context[PLAN_CONTEXT_WEBAUTHN_CHALLENGE] = registration_options.challenge
        return AuthenticatorWebAuthnChallenge(
            data={
                "registration": options_to_json_dict(registration_options),
            }
        )

    def get_response_instance(self, data: QueryDict) -> AuthenticatorWebAuthnChallengeResponse:
        response: AuthenticatorWebAuthnChallengeResponse = super().get_response_instance(data)
        response.request = self.request
        response.user = self.get_pending_user()
        return response

    def challenge_invalid(self, response):
        stage: AuthenticatorWebAuthnStage = self.executor.current_stage
        self.executor.plan.context.setdefault(PLAN_CONTEXT_WEBAUTHN_ATTEMPT, 0)
        self.executor.plan.context[PLAN_CONTEXT_WEBAUTHN_ATTEMPT] += 1
        if (
            stage.max_attempts > 0
            and self.executor.plan.context[PLAN_CONTEXT_WEBAUTHN_ATTEMPT] >= stage.max_attempts
        ):
            return self.executor.stage_invalid(
                _("Exceeded maximum attempts. Contact your {brand} administrator for help.").format(
                    brand=self.request.brand.branding_title
                )
            )
        return super().challenge_invalid(response)

    def challenge_valid(self, response: ChallengeResponse) -> HttpResponse:
        # Webauthn Challenge has already been validated
        webauthn_credential: VerifiedRegistrationData = response.validated_data["response"]
        try:
            with transaction.atomic():
                create_device(self.get_pending_user(), get_rp_id(self.request), webauthn_credential)
        except IntegrityError:
            return self.executor.stage_invalid(message=_("Credential ID already exists."))
        self.executor.plan.context.pop(PLAN_CONTEXT_WEBAUTHN_POLICY, None)
        # The registration challenge has been answered. Remove it, as the authenticator validation
        # stage uses the same key and keeps a pending challenge until it's answered
        self.executor.plan.context.pop(PLAN_CONTEXT_WEBAUTHN_CHALLENGE, None)
        return self.executor.stage_ok()
