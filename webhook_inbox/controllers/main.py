import json
import logging

from psycopg2 import IntegrityError

from odoo import http
from odoo.http import request

_logger = logging.getLogger(__name__)

MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MB


class WebhookInboxController(http.Controller):

    @http.route(
        "/webhook/<string:code>",
        type="http",
        auth="public",
        methods=["POST"],
        csrf=False,
        save_session=False,
    )
    def receive(self, code, **kwargs):
        endpoint = request.env["webhook.endpoint"].sudo().search([("code", "=", code)], limit=1)
        if not endpoint:
            return request.make_json_response({"status": "not_found"}, status=404)

        body = request.httprequest.get_data(cache=False)
        if len(body) > MAX_BODY_BYTES:
            return request.make_json_response({"status": "payload_too_large"}, status=413)

        headers = dict(request.httprequest.headers)
        error = endpoint._check_request(body, headers)
        if error:
            _logger.info("Webhook %s rejected: %s", code, error)
            return request.make_json_response({"status": "rejected", "reason": error}, status=401)

        Event = request.env["webhook.event"].sudo()
        uid = endpoint._get_event_uid(body, headers)
        if Event.search_count([("endpoint_id", "=", endpoint.id), ("event_uid", "=", uid)]):
            return request.make_json_response({"status": "duplicate", "event_id": uid})

        try:
            with request.env.cr.savepoint():
                event = Event.create({
                    "endpoint_id": endpoint.id,
                    "event_uid": uid,
                    "payload": body.decode("utf-8", errors="replace"),
                    "headers": json.dumps(Event._filter_headers(headers)),
                    "remote_addr": request.httprequest.remote_addr,
                })
        except IntegrityError:
            # Two identical deliveries raced each other: the first one wins.
            return request.make_json_response({"status": "duplicate", "event_id": uid})

        # Process as soon as possible, outside the request.
        request.env.ref("webhook_inbox.ir_cron_process_events").sudo()._trigger()
        return request.make_json_response({"status": "queued", "event_id": uid, "id": event.id})
