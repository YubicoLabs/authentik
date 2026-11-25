"""Delegated enrollment participates in native administrator-defined API checks."""

from django.urls import reverse
from rest_framework.test import APITestCase

from authentik.core.tests.utils import create_test_admin_user
from authentik.lib.generators import generate_id
from authentik.rbac.apps import EnableCustomPermissions
from authentik.rbac.models import PermissionCheck
from authentik.stages.authenticator_webauthn.tests import test_enrollment_authorization as helpers

PREFIX = "authenticators/admin/webauthn-enrollments"


class TestEnrollmentEndpointChecks(APITestCase):
    restore_origin = helpers.TestEnrollmentAuthorization.restore_origin
    prepare = helpers.TestEnrollmentAuthorization.prepare
    complete = helpers.TestEnrollmentAuthorization.complete

    def setUp(self):
        helpers.TestEnrollmentAuthorization.setUp(self)
        previous = EnableCustomPermissions.get()
        EnableCustomPermissions.set(True)
        self.addCleanup(EnableCustomPermissions.set, previous)

    def check(self, endpoint, expression):
        return PermissionCheck.objects.create(
            name=generate_id(), endpoints=[endpoint], expression=expression
        )

    def test_object_check_can_deny_completion_without_consuming_attempt(self):
        original = self.prepare(completed=False)
        check = self.check(
            f"{PREFIX}:complete",
            "def has_object_permission(request, obj):\n    return False",
        )
        self.assertEqual(self.complete().status_code, 403)
        self.assertEqual(self.client.get(self.detail_url).data, original)
        check.delete()
        self.assertEqual(self.complete().status_code, 200)

    def test_object_check_can_deny_cancellation(self):
        original = self.prepare(completed=False)
        self.check(
            f"{PREFIX}:cancel",
            "def has_object_permission(request, obj):\n    return False",
        )
        url = reverse(
            "authentik_api:admin-webauthnenrollment-cancel", kwargs={"pk": original["pk"]}
        )
        self.assertEqual(self.client.post(url, {}, format="json").status_code, 403)
        self.assertEqual(self.client.get(self.detail_url).data, original)

    def test_native_list_check_hides_enrollments_from_list_and_retrieve(self):
        self.prepare(completed=False)
        self.check(
            f"{PREFIX}:list", "def narrow_list(request, queryset):\n    return queryset.none()"
        )
        listed = self.client.get(reverse("authentik_api:admin-webauthnenrollment-list"))
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.data["results"], [])
        self.assertEqual(self.client.get(self.detail_url).status_code, 404)

    def test_target_and_stage_list_policies_are_rechecked_at_completion(self):
        self.prepare(completed=False)
        for endpoint in ("core/users:list", "stages/authenticator/webauthn:list"):
            with self.subTest(endpoint=endpoint):
                check = self.check(
                    endpoint, "def narrow_list(request, queryset):\n    return queryset.none()"
                )
                try:
                    self.assertEqual(self.complete().status_code, 403)
                finally:
                    check.delete()
        self.assertEqual(self.complete().status_code, 200)

    def test_widening_list_cannot_transfer_another_issuers_attempt(self):
        owned = self.prepare(completed=False)
        self.client.force_login(create_test_admin_user())
        other = self.client.post(
            reverse("authentik_api:admin-webauthnenrollment-begin"),
            {"user": self.user.pk, "stage": str(self.stage.pk), "idempotency_key": "other-issuer"},
            format="json",
        )
        self.assertEqual(other.status_code, 201)
        self.client.force_login(self.caller)
        self.caller.remove_perms_from_managed_role(
            "authentik_stages_authenticator_webauthn.change_webauthnenrollment"
        )
        for action in ("retrieve", "complete", "cancel"):
            self.check(
                f"{PREFIX}:{action}",
                "def has_permission(request):\n    raise PermissionCheckSkipException\n"
                "def has_object_permission(request, obj):\n    raise PermissionCheckSkipException",
            )
        self.check(
            f"{PREFIX}:list",
            "def widen_list(request, queryset):\n    return queryset.model.objects.all()",
        )
        listed = self.client.get(reverse("authentik_api:admin-webauthnenrollment-list"))
        self.assertEqual(listed.status_code, 200)
        self.assertCountEqual(
            [str(item["pk"]) for item in listed.data["results"]],
            [str(owned["pk"]), str(other.data["pk"])],
        )
        for action in ("detail", "complete", "cancel"):
            with self.subTest(action=action):
                url = reverse(
                    f"authentik_api:admin-webauthnenrollment-{action}",
                    kwargs={"pk": other.data["pk"]},
                )
                response = (
                    self.client.get(url)
                    if action == "detail"
                    else self.client.post(
                        url, self.body if action == "complete" else {}, format="json"
                    )
                )
                self.assertEqual(response.status_code, 404 if action == "complete" else 200)
        # An explicit administrator override does not transfer completion ownership.
        self.assertEqual(self.complete().status_code, 200)

    def test_request_check_can_deny_begin_despite_role_grants(self):
        self.check(f"{PREFIX}:begin", "def has_permission(request):\n    return False")
        begun = self.client.post(
            reverse("authentik_api:admin-webauthnenrollment-begin"),
            {"user": self.user.pk, "stage": str(self.stage.pk), "idempotency_key": "denied-begin"},
            format="json",
        )
        self.assertEqual(begun.status_code, 403)

    def test_hidden_attempt_does_not_return_options_through_begin_retry(self):
        url = reverse("authentik_api:admin-webauthnenrollment-begin")
        body = {
            "user": self.user.pk,
            "stage": str(self.stage.pk),
            "idempotency_key": "hidden-retry",
        }
        begun = self.client.post(url, body, format="json")
        self.assertEqual(begun.status_code, 201)
        self.check(
            f"{PREFIX}:list", "def narrow_list(request, queryset):\n    return queryset.none()"
        )
        self.assertEqual(self.client.post(url, body, format="json").status_code, 404)
