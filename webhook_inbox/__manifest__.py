{
    "name": "Webhook Inbox",
    "summary": "Receive webhooks safely: HMAC signatures, anti-replay, "
               "idempotency, queue, retries and server-action processing",
    "version": "18.0.1.0.1",
    "category": "Extra Tools",
    "author": "Hidelberg Martínez (Hideldev)",
    "website": "https://hidel21.github.io/",
    "support": "hidelmartinez21@gmail.com",
    "license": "LGPL-3",
    "depends": ["base"],
    "data": [
        "security/ir.model.access.csv",
        "data/ir_cron.xml",
        "views/webhook_event_views.xml",
        "views/webhook_endpoint_views.xml",
        "views/menus.xml",
    ],
    "images": ["static/description/banner.png"],
    "application": True,
    "installable": True,
}
