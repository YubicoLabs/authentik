"""Read-only representation of a delegated enrollment record."""

from django.utils.timezone import now
from rest_framework.fields import ChoiceField

from authentik.core.api.utils import ModelSerializer
from authentik.stages.authenticator_webauthn.models import WebAuthnEnrollment


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
