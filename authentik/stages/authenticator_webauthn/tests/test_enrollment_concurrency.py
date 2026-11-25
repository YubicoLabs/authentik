"""Public API outcomes under controlled, real PostgreSQL lock contention."""

from concurrent.futures import ThreadPoolExecutor
from threading import Event

from django.db import close_old_connections, connection
from django.urls import reverse
from rest_framework.test import APIClient, APITransactionTestCase
from webauthn.helpers.base64url_to_bytes import base64url_to_bytes

from authentik.core.tests.utils import create_test_admin_user, create_test_user
from authentik.lib.config import CONFIG, UNSET
from authentik.lib.generators import generate_id
from authentik.stages.authenticator_webauthn.models import AuthenticatorWebAuthnStage
from authentik.stages.authenticator_webauthn.tests.test_enrollment import (
    SoftwareES256Credential,
)


class TestEnrollmentConcurrency(APITransactionTestCase):
    """Independent API clients share committed fixtures, not a test transaction."""

    def setUp(self):
        self.previous_origin = CONFIG.get("webauthn_enrollment.origin", default=UNSET)
        CONFIG.set("webauthn_enrollment.origin", "https://testserver")
        self.addCleanup(self.restore_origin)
        self.admin = create_test_admin_user()
        self.user = create_test_user()
        self.stage = AuthenticatorWebAuthnStage.objects.create(name=generate_id())
        self.client.force_authenticate(self.admin)
        begun = self.client.post(
            reverse("authentik_api:admin-webauthnenrollment-begin"),
            {"user": self.user.pk, "stage": str(self.stage.pk), "idempotency_key": generate_id()},
            format="json",
        )
        self.assertEqual(begun.status_code, 201)
        self.enrollment = begun.data
        credential = SoftwareES256Credential(begun.data["rp_id"], begun.data["origin"])
        self.body = {
            "response": credential.registration_response(
                base64url_to_bytes(begun.data["registration"]["challenge"])
            )
        }

    def restore_origin(self):
        if self.previous_origin is UNSET:
            CONFIG.delete("webauthn_enrollment.origin")
        else:
            CONFIG.set("webauthn_enrollment.origin", self.previous_origin)

    def url(self, action):
        return reverse(
            f"authentik_api:admin-webauthnenrollment-{action}",
            kwargs={"pk": self.enrollment["pk"]},
        )

    def contend(self, first_action, second_action):
        """Hold the first actual row lock while the second request reaches it.

        Instrument only the database execution boundary: SQL and results are
        unchanged. No sleeps, mocked verifier, fake locks or private API hooks.
        The SQL gate is deliberately narrow; a changed locking strategy must
        update this scheduling harness rather than silently become a serial test.
        """
        locked, competing, release = Event(), Event(), Event()
        stage_contention = "begin" in {first_action, second_action}

        def request(action, first):
            close_old_connections()
            observed = False

            def schedule(execute, sql, params, many, context):
                nonlocal observed
                target = (
                    not observed
                    and (
                        "FOR UPDATE" in sql
                        or (action in {"revoke", "delete-stage"} and sql.startswith("UPDATE "))
                    )
                    and (
                        '"authentik_stages_authenticator_webauthn_authenticator' in sql
                        if stage_contention
                        else '"authentik_stages_authenticator_webauthn_webauthnenrollment"' in sql
                    )
                )
                if not target:
                    return execute(sql, params, many, context)
                observed = True
                if not first:
                    competing.set()
                result = execute(sql, params, many, context)
                if first:
                    locked.set()
                    if not release.wait(10):
                        raise TimeoutError("First enrollment lock was not released")
                return result

            try:
                client = APIClient()
                client.force_authenticate(self.admin)
                with connection.execute_wrapper(schedule):
                    if action == "revoke":
                        result = client.delete(self.device_url)
                    elif action == "delete-stage":
                        result = client.delete(
                            reverse(
                                "authentik_api:authenticatorwebauthnstage-detail",
                                kwargs={"pk": self.stage.pk},
                            )
                        )
                    elif action == "begin":
                        result = client.post(
                            reverse("authentik_api:admin-webauthnenrollment-begin"),
                            {
                                "user": self.user.pk,
                                "stage": str(self.stage.pk),
                                "idempotency_key": "racing-begin",
                            },
                            format="json",
                        )
                    else:
                        result = client.post(
                            self.url(action),
                            self.body if action == "complete" else {},
                            format="json",
                        )
                if not observed:
                    raise AssertionError("Request never reached the enrollment lock")
                return result
            finally:
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            first = pool.submit(request, first_action, True)
            try:
                self.assertTrue(locked.wait(10), "First request did not acquire enrollment lock")
                second = pool.submit(request, second_action, False)
                self.assertTrue(competing.wait(10), "Second request did not reach enrollment lock")
            finally:
                release.set()
            return first.result(timeout=15), second.result(timeout=15)

    def assert_devices(self, expected_ids):
        listed = self.client.get(reverse("authentik_api:admin-webauthndevice-list"))
        self.assertEqual(listed.status_code, 200)
        self.assertEqual(listed.data["pagination"]["count"], len(expected_ids))
        self.assertEqual({device["pk"] for device in listed.data["results"]}, expected_ids)

    def test_duplicate_completions_return_one_device(self):
        first, second = self.contend("complete", "complete")
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.data, second.data)
        self.assertEqual(first.data["status"], "completed")
        self.assertIsNotNone(first.data["device"])
        self.assert_devices({first.data["device"]})
        inspected = self.client.get(self.url("detail"))
        self.assertEqual(inspected.status_code, 200)
        self.assertEqual(inspected.data, first.data)

    def test_completion_wins_before_cancellation(self):
        completed, cancelled = self.contend("complete", "cancel")
        self.assertEqual(completed.status_code, 200)
        self.assertEqual(completed.data["status"], "completed")
        self.assertEqual(cancelled.status_code, 400)
        self.assert_devices({completed.data["device"]})
        inspected = self.client.get(self.url("detail"))
        self.assertEqual(inspected.status_code, 200)
        self.assertEqual(inspected.data, completed.data)
        replay = self.client.post(self.url("complete"), self.body, format="json")
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.data, completed.data)

    def test_cancellation_wins_before_completion(self):
        cancelled, completed = self.contend("cancel", "complete")
        self.assertEqual(cancelled.status_code, 200)
        self.assertEqual(cancelled.data["status"], "cancelled")
        self.assertIsNone(cancelled.data["device"])
        self.assertEqual(completed.status_code, 400)
        self.assert_devices(set())
        inspected = self.client.get(self.url("detail"))
        self.assertEqual(inspected.status_code, 200)
        self.assertEqual(inspected.data, cancelled.data)
        replay = self.client.post(self.url("cancel"), {}, format="json")
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.data, cancelled.data)

    def check_revocation_race(self, first_action):
        completed = self.client.post(self.url("complete"), self.body, format="json")
        self.assertEqual(completed.status_code, 200)
        self.device_url = reverse(
            "authentik_api:admin-webauthndevice-detail",
            kwargs={"pk": completed.data["device"]},
        )
        second_action = "complete" if first_action == "revoke" else "revoke"
        first, second = self.contend(first_action, second_action)
        revoked, replay = (first, second) if first_action == "revoke" else (second, first)
        self.assertEqual(revoked.status_code, 204)
        self.assertEqual(replay.status_code, 400 if first_action == "revoke" else 200)
        if first_action == "complete":
            self.assertEqual(replay.data, completed.data)
        self.assertEqual(self.client.get(self.device_url).status_code, 404)
        self.assert_devices(set())
        inspected = self.client.get(self.url("detail"))
        self.assertEqual(inspected.status_code, 200)
        self.assertEqual(inspected.data["status"], "completed")
        self.assertIsNone(inspected.data["device"])
        for _ in range(2):
            rejected = self.client.post(self.url("complete"), self.body, format="json")
            self.assertEqual(rejected.status_code, 400)
        self.assert_devices(set())

    def test_revocation_before_replay_cannot_resurrect_device(self):
        self.check_revocation_race("revoke")

    def test_replay_before_revocation_cannot_preserve_device(self):
        self.check_revocation_race("complete")

    def test_stage_deletion_before_completion_cannot_create_a_device(self):
        deleted, completed = self.contend("delete-stage", "complete")
        self.assertEqual(deleted.status_code, 204)
        self.assertEqual(completed.status_code, 400)
        self.assertEqual(completed.data["code"], "enrollment_policy_unavailable")
        self.assert_devices(set())

    def test_completion_before_stage_deletion_remains_recoverable(self):
        completed, deleted = self.contend("complete", "delete-stage")
        self.assertEqual(completed.status_code, 200)
        self.assertEqual(deleted.status_code, 204)
        replay = self.client.post(self.url("complete"), self.body, format="json")
        self.assertEqual(replay.status_code, 200)
        self.assertEqual(replay.data["device"], completed.data["device"])
        self.assertIsNone(replay.data["stage"])
        self.assert_devices({completed.data["device"]})

    def test_begin_during_stage_deletion_does_not_break_deletion(self):
        deleted, begun = self.contend("delete-stage", "begin")
        self.assertEqual(deleted.status_code, 204)
        self.assertIn(begun.status_code, {400, 404})

    def test_begin_before_stage_deletion_retains_an_unusable_attempt(self):
        begun, deleted = self.contend("begin", "delete-stage")
        self.assertEqual(begun.status_code, 201)
        self.assertEqual(deleted.status_code, 204)
        inspected = self.client.get(
            reverse(
                "authentik_api:admin-webauthnenrollment-detail", kwargs={"pk": begun.data["pk"]}
            )
        )
        self.assertEqual(inspected.status_code, 200)
        self.assertIsNone(inspected.data["stage"])
