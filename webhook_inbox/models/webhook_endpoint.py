import hashlib
import hmac
import re
import secrets
import time

from odoo import _, api, fields, models
from odoo.exceptions import ValidationError

CODE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")


class WebhookEndpoint(models.Model):
    _name = "webhook.endpoint"
    _description = "Webhook Endpoint"
    _order = "name"

    name = fields.Char(required=True)
    code = fields.Char(
        required=True,
        copy=False,
        help="Public identifier used in the URL: /webhook/<code>. "
             "Lowercase letters, digits, '-' and '_' only.",
    )
    active = fields.Boolean(default=True)
    url = fields.Char(string="Webhook URL", compute="_compute_url")
    description = fields.Text()

    # --- Security -----------------------------------------------------------------
    signature_scheme = fields.Selection(
        [
            ("none", "No signature (not recommended)"),
            ("body", "HMAC-SHA256 of the raw body"),
            ("timestamp_body", "HMAC-SHA256 of '<timestamp>.<raw body>'"),
        ],
        default="body",
        required=True,
    )
    secret = fields.Char(
        groups="base.group_system",
        copy=False,
        help="Shared secret used to compute the HMAC signature.",
    )
    signature_header = fields.Char(default="X-Signature", required=True)
    signature_prefix = fields.Char(
        help="Optional prefix the sender puts before the hex digest, e.g. 'sha256='.",
    )
    timestamp_header = fields.Char(
        help="Header carrying the UNIX timestamp of the request. When set, requests "
             "older than the tolerance are rejected (anti-replay).",
    )
    timestamp_tolerance = fields.Integer(
        string="Tolerance (seconds)",
        default=300,
        help="Maximum accepted age of a request, in seconds.",
    )
    event_id_header = fields.Char(
        string="Event ID Header",
        help="Header carrying a unique event identifier. When empty, the SHA-256 "
             "of the body is used, so identical payloads are stored only once.",
    )

    # --- Processing -----------------------------------------------------------------
    action_id = fields.Many2one(
        "ir.actions.server",
        string="Processing Action",
        domain="[('model_id.model', '=', 'webhook.event')]",
        help="Server action executed for every event. In Python code the event is "
             "available as 'record' and record.get_json() returns the parsed payload.",
    )
    max_attempts = fields.Integer(default=5, help="Attempts before an event is left as failed.")
    retention_days = fields.Integer(
        default=30,
        help="Processed events older than this are deleted automatically. 0 keeps them forever.",
    )

    event_ids = fields.One2many("webhook.event", "endpoint_id")
    event_count = fields.Integer(compute="_compute_event_stats")
    failed_count = fields.Integer(compute="_compute_event_stats")
    pending_count = fields.Integer(compute="_compute_event_stats")

    _sql_constraints = [
        ("code_unique", "unique(code)", "The endpoint code must be unique."),
    ]

    # ------------------------------------------------------------------------------
    @api.constrains("code")
    def _check_code(self):
        for endpoint in self:
            if not CODE_RE.match(endpoint.code or ""):
                raise ValidationError(_(
                    "Invalid code '%s': use 2-63 lowercase letters, digits, '-' or '_'.",
                    endpoint.code,
                ))

    @api.constrains("signature_scheme", "timestamp_header")
    def _check_timestamp_scheme(self):
        for endpoint in self:
            if endpoint.signature_scheme == "timestamp_body" and not endpoint.timestamp_header:
                raise ValidationError(_("The '<timestamp>.<body>' scheme needs a timestamp header."))

    @api.depends("code")
    def _compute_url(self):
        base = self.get_base_url()
        for endpoint in self:
            endpoint.url = f"{base}/webhook/{endpoint.code}" if endpoint.code else False

    def _compute_event_stats(self):
        data = self.env["webhook.event"]._read_group(
            [("endpoint_id", "in", self.ids)], ["endpoint_id", "state"], ["__count"],
        )
        stats = {}
        for endpoint, state, count in data:
            stats.setdefault(endpoint.id, {})[state] = count
        for endpoint in self:
            by_state = stats.get(endpoint.id, {})
            endpoint.event_count = sum(by_state.values())
            endpoint.failed_count = by_state.get("failed", 0)
            endpoint.pending_count = by_state.get("pending", 0) + by_state.get("error", 0)

    # ------------------------------------------------------------------------------
    def action_generate_secret(self):
        for endpoint in self:
            endpoint.secret = secrets.token_hex(32)
        return True

    def action_view_events(self):
        self.ensure_one()
        action = self.env["ir.actions.actions"]._for_xml_id("webhook_inbox.action_webhook_event")
        action["domain"] = [("endpoint_id", "=", self.id)]
        action["context"] = {"default_endpoint_id": self.id}
        return action

    # ------------------------------------------------------------------------------
    # Request validation (called by the controller with sudo)
    # ------------------------------------------------------------------------------
    @staticmethod
    def _get_header(headers, name):
        if not name:
            return None
        lowered = name.lower()
        for key, value in headers.items():
            if key.lower() == lowered:
                return value
        return None

    def _check_request(self, body, headers, now=None):
        """Return None when the request is valid, otherwise a short error message."""
        self.ensure_one()
        timestamp = None
        if self.timestamp_header:
            timestamp = self._get_header(headers, self.timestamp_header)
            try:
                ts_value = int(float(timestamp))
            except (TypeError, ValueError):
                return "missing or invalid timestamp"
            if abs((now or time.time()) - ts_value) > max(self.timestamp_tolerance, 0):
                return "timestamp outside tolerance"

        if self.signature_scheme == "none":
            return None
        if not self.secret:
            return "endpoint has no secret configured"
        received = self._get_header(headers, self.signature_header) or ""
        prefix = self.signature_prefix or ""
        if prefix and received.startswith(prefix):
            received = received[len(prefix):]
        message = body
        if self.signature_scheme == "timestamp_body":
            message = f"{timestamp}.".encode() + body
        expected = hmac.new(self.secret.encode(), message, hashlib.sha256).hexdigest()
        if not received or not hmac.compare_digest(expected, received.strip().lower()):
            return "invalid signature"
        return None

    def _get_event_uid(self, body, headers):
        self.ensure_one()
        uid = self._get_header(headers, self.event_id_header)
        if uid:
            return uid.strip()[:255]
        return "sha256:" + hashlib.sha256(body).hexdigest()
