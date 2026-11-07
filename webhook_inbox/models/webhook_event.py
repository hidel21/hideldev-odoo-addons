import json
import logging
from datetime import timedelta

import psycopg2

from odoo import _, api, fields, models
from odoo.exceptions import UserError
from odoo.service.model import PG_CONCURRENCY_ERRORS_TO_RETRY

_logger = logging.getLogger(__name__)

BATCH_SIZE = 50
# Headers worth keeping for troubleshooting. Anything else (cookies, auth) is dropped.
STORED_HEADER_PREFIXES = ("x-", "content-type", "user-agent")
# Retry delays grow exponentially: 1, 2, 4, 8... minutes, capped at one hour.
RETRY_BASE_MINUTES = 1
RETRY_MAX_MINUTES = 60


class WebhookEvent(models.Model):
    _name = "webhook.event"
    _description = "Webhook Event"
    _order = "id desc"
    _rec_name = "event_uid"

    endpoint_id = fields.Many2one("webhook.endpoint", required=True, ondelete="cascade", index=True)
    event_uid = fields.Char(string="Event ID", required=True, index=True, readonly=True)
    state = fields.Selection(
        [
            ("pending", "Pending"),
            ("done", "Done"),
            ("error", "Error (will retry)"),
            ("failed", "Failed"),
        ],
        default="pending",
        required=True,
        index=True,
    )
    received_at = fields.Datetime(default=fields.Datetime.now, required=True, readonly=True)
    processed_at = fields.Datetime(readonly=True)
    attempts = fields.Integer(readonly=True)
    next_attempt_at = fields.Datetime(string="Next attempt", readonly=True, index=True)
    last_error = fields.Text(readonly=True)
    remote_addr = fields.Char(string="Sender IP", readonly=True)
    headers = fields.Text(readonly=True)
    payload = fields.Text(readonly=True)
    payload_pretty = fields.Text(string="Payload (formatted)", compute="_compute_payload_pretty")

    _sql_constraints = [
        ("uid_unique", "unique(endpoint_id, event_uid)", "This event was already received."),
    ]

    @api.depends("payload")
    def _compute_payload_pretty(self):
        for event in self:
            try:
                event.payload_pretty = json.dumps(json.loads(event.payload or ""), indent=2, ensure_ascii=False)
            except ValueError:
                event.payload_pretty = event.payload

    # ------------------------------------------------------------------------------
    # Helpers for server actions
    # ------------------------------------------------------------------------------
    def get_json(self):
        """Parsed JSON payload of the event (dict or list). Raises UserError if invalid."""
        self.ensure_one()
        try:
            return json.loads(self.payload or "")
        except ValueError as exc:
            raise UserError(_("The payload is not valid JSON: %s", exc)) from exc

    def get_header(self, name):
        self.ensure_one()
        return self.endpoint_id._get_header(json.loads(self.headers or "{}"), name)

    @api.model
    def _filter_headers(self, headers):
        return {
            key: value for key, value in headers.items()
            if key.lower().startswith(STORED_HEADER_PREFIXES)
        }

    # ------------------------------------------------------------------------------
    # Processing
    # ------------------------------------------------------------------------------
    def _lock_for_processing(self):
        """Lock the events that are not done yet, skipping rows another worker holds.

        The cron and a user clicking "Process now" can run at the same time: each one
        only gets the events nobody else is processing.
        """
        if not self:
            return self
        self.flush_model(["state"])
        self.env.cr.execute(
            "SELECT id FROM webhook_event WHERE id IN %s AND state != 'done' "
            "ORDER BY id FOR UPDATE SKIP LOCKED",
            [tuple(self.ids)],
        )
        events = self.browse([row[0] for row in self.env.cr.fetchall()])
        events.invalidate_recordset()
        return events

    def _process(self):
        """Run the endpoint's server action on each event, isolating failures."""
        for event in self._lock_for_processing():
            action = event.endpoint_id.action_id
            attempts = event.attempts + 1
            try:
                with self.env.cr.savepoint():
                    if action:
                        action.with_context(
                            active_model=event._name, active_id=event.id, active_ids=event.ids,
                        ).run()
            except Exception as exc:  # noqa: BLE001 - every failure must be recorded
                if isinstance(exc, psycopg2.Error) and exc.pgcode in PG_CONCURRENCY_ERRORS_TO_RETRY:
                    raise  # let Odoo retry the whole transaction
                _logger.warning("Webhook event %s failed: %s", event.id, exc)
                exhausted = attempts >= max(event.endpoint_id.max_attempts, 1)
                delay = min(RETRY_BASE_MINUTES * 2 ** (attempts - 1), RETRY_MAX_MINUTES)
                next_attempt = False if exhausted else fields.Datetime.now() + timedelta(minutes=delay)
                event.write({
                    "attempts": attempts,
                    "state": "failed" if exhausted else "error",
                    "last_error": str(exc)[:2000],
                    "next_attempt_at": next_attempt,
                })
                if next_attempt:
                    self.env.ref("webhook_inbox.ir_cron_process_events").sudo()._trigger(at=next_attempt)
            else:
                event.write({
                    "attempts": attempts,
                    "state": "done",
                    "processed_at": fields.Datetime.now(),
                    "last_error": False,
                    "next_attempt_at": False,
                })

    def action_process(self):
        self._process()
        return True

    def action_retry(self):
        self.write({"state": "pending", "attempts": 0, "last_error": False, "next_attempt_at": False})
        self._process()
        return True

    def action_mark_done(self):
        self.write({"state": "done", "processed_at": fields.Datetime.now(), "next_attempt_at": False})
        return True

    @api.model
    def _cron_process(self):
        events = self.search([
            "|",
            ("state", "=", "pending"),
            "&", ("state", "=", "error"), ("next_attempt_at", "<=", fields.Datetime.now()),
        ], order="id", limit=BATCH_SIZE)
        events._process()
        if len(events) == BATCH_SIZE:
            self.env.ref("webhook_inbox.ir_cron_process_events")._trigger()

    @api.model
    def _cron_cleanup(self):
        for endpoint in self.env["webhook.endpoint"].with_context(active_test=False).search(
                [("retention_days", ">", 0)]):
            limit = fields.Datetime.now() - timedelta(days=endpoint.retention_days)
            self.search([
                ("endpoint_id", "=", endpoint.id),
                ("state", "=", "done"),
                ("received_at", "<", limit),
            ]).unlink()
