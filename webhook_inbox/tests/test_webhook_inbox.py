import hashlib
import hmac
import json
import time
from datetime import timedelta

from odoo import fields
from odoo.tests import HttpCase, tagged


@tagged("post_install", "-at_install")
class TestWebhookInbox(HttpCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.action = cls.env["ir.actions.server"].create({
            "name": "Create partner from webhook",
            "model_id": cls.env.ref("webhook_inbox.model_webhook_event").id,
            "state": "code",
            "code": "data = record.get_json()\n"
                    "if data.get('fail'):\n"
                    "    raise UserError('boom')\n"
                    "env['res.partner'].create({'name': data['name']})",
        })
        cls.endpoint = cls.env["webhook.endpoint"].create({
            "name": "Test",
            "code": "test-hook",
            "secret": "s3cr3t",
            "signature_scheme": "body",
            "signature_header": "X-Signature",
            "signature_prefix": "sha256=",
            "event_id_header": "X-Event-Id",
            "action_id": cls.action.id,
            "max_attempts": 2,
        })

    # ------------------------------------------------------------------------------
    def _post(self, payload, event_id=None, secret="s3cr3t", headers=None, code="test-hook"):
        body = json.dumps(payload).encode()
        sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        all_headers = {"Content-Type": "application/json", "X-Signature": "sha256=" + sig}
        if event_id:
            all_headers["X-Event-Id"] = event_id
        all_headers.update(headers or {})
        return self.url_open(f"/webhook/{code}", data=body, headers=all_headers)

    def _events(self):
        return self.env["webhook.event"].search([("endpoint_id", "=", self.endpoint.id)])

    # ------------------------------------------------------------------------------
    def test_valid_request_is_queued_and_processed(self):
        response = self._post({"name": "Ada Lovelace"}, event_id="evt_1")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "queued")
        event = self._events()
        self.assertEqual(len(event), 1)
        self.assertEqual(event.state, "pending")
        self.assertEqual(event.event_uid, "evt_1")
        self.assertNotIn("Cookie", json.loads(event.headers))

        self.env["webhook.event"]._cron_process()
        self.assertEqual(event.state, "done")
        self.assertTrue(self.env["res.partner"].search([("name", "=", "Ada Lovelace")]))

    def test_invalid_signature_is_rejected(self):
        response = self._post({"name": "Mallory"}, event_id="evt_2", secret="wrong")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()["reason"], "invalid signature")
        self.assertFalse(self._events())

    def test_missing_signature_is_rejected(self):
        body = b'{"name": "Eve"}'
        response = self.url_open("/webhook/test-hook", data=body, headers={"Content-Type": "application/json"})
        self.assertEqual(response.status_code, 401)
        self.assertFalse(self._events())

    def test_unknown_or_archived_endpoint_returns_404(self):
        self.assertEqual(self._post({"name": "x"}, code="does-not-exist").status_code, 404)
        self.endpoint.active = False
        self.assertEqual(self._post({"name": "x"}).status_code, 404)

    def test_duplicate_event_is_stored_once(self):
        self.assertEqual(self._post({"name": "Grace"}, event_id="evt_3").json()["status"], "queued")
        second = self._post({"name": "Grace"}, event_id="evt_3")
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.json()["status"], "duplicate")
        self.assertEqual(len(self._events()), 1)

    def test_body_hash_used_when_no_event_id(self):
        self.endpoint.event_id_header = False
        self._post({"name": "Linus"})
        self._post({"name": "Linus"})
        self._post({"name": "Linus T."})
        self.assertEqual(len(self._events()), 2)
        self.assertTrue(all(uid.startswith("sha256:") for uid in self._events().mapped("event_uid")))

    def test_timestamp_scheme_and_replay_window(self):
        self.endpoint.write({"timestamp_header": "X-Timestamp", "signature_scheme": "timestamp_body"})
        body = b'{"name": "Margaret"}'

        def signed(ts):
            sig = hmac.new(b"s3cr3t", f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
            return {"Content-Type": "application/json", "X-Signature": "sha256=" + sig, "X-Timestamp": str(ts)}

        now = int(time.time())
        ok = self.url_open("/webhook/test-hook", data=body, headers=signed(now))
        self.assertEqual(ok.status_code, 200)
        old = self.url_open("/webhook/test-hook", data=body, headers=signed(now - 3600))
        self.assertEqual(old.status_code, 401)
        self.assertEqual(old.json()["reason"], "timestamp outside tolerance")

    def test_failures_are_retried_then_marked_failed(self):
        self._post({"fail": True}, event_id="evt_4")
        event = self._events()
        Event = self.env["webhook.event"]
        Event._cron_process()
        self.assertEqual(event.state, "error")
        self.assertIn("boom", event.last_error)
        # The retry waits (exponential backoff): running the cron right away does nothing.
        self.assertGreater(event.next_attempt_at, fields.Datetime.now())
        Event._cron_process()
        self.assertEqual(event.attempts, 1)
        # Once the delay has passed, the event is retried and, at max_attempts, marked failed.
        event.next_attempt_at = fields.Datetime.now() - timedelta(seconds=1)
        Event._cron_process()
        self.assertEqual(event.state, "failed")
        self.assertFalse(event.next_attempt_at)
        self.assertEqual(event.attempts, 2)
        # A failed event is not picked up again by the cron, but can be retried manually.
        Event._cron_process()
        self.assertEqual(event.attempts, 2)
        event.action_retry()
        self.assertEqual(event.attempts, 1)

    def test_cleanup_removes_only_old_processed_events(self):
        self._post({"name": "Old"}, event_id="old")
        self._post({"name": "Recent"}, event_id="recent")
        self.env["webhook.event"]._cron_process()
        old = self._events().filtered(lambda e: e.event_uid == "old")
        old.received_at = fields.Datetime.now() - timedelta(days=self.endpoint.retention_days + 1)
        self.env["webhook.event"]._cron_cleanup()
        self.assertEqual(self._events().mapped("event_uid"), ["recent"])

    def test_code_validation(self):
        with self.assertRaises(Exception):
            self.env["webhook.endpoint"].create({"name": "Bad", "code": "Bad Code!"})
        self.assertEqual(self.endpoint.url, self.endpoint.get_base_url() + "/webhook/test-hook")

    def test_done_events_are_not_processed_twice(self):
        self._post({"name": "Barbara Liskov"}, event_id="evt_once")
        event = self._events()
        event.action_process()
        event.action_process()
        self.env["webhook.event"]._cron_process()
        self.assertEqual(event.state, "done")
        self.assertEqual(event.attempts, 1)
        self.assertEqual(self.env["res.partner"].search_count([("name", "=", "Barbara Liskov")]), 1)
