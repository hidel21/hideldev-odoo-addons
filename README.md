# Hideldev Odoo Addons

Free Odoo modules by **Hidelberg Martínez (Hideldev)** — senior Odoo developer (v14–v19).
🌐 [hidel21.github.io](https://hidel21.github.io/en/) · ✉️ hidelmartinez21@gmail.com

Each branch targets one Odoo version (`18.0`, …). Modules live at the root of the branch.

## Modules

| Module | Version | Description |
|---|---|---|
| [webhook_inbox](webhook_inbox) | 18.0 | Receive webhooks safely: HMAC signatures, anti-replay, idempotency, queue, retries with backoff and server-action processing. |

## Webhook Inbox

Receive webhooks from any system (Stripe, HubSpot, Shopify, your own apps) at `/webhook/<code>`,
verify them, store them once and process them in the background with a regular Odoo server action.

**Features**

- HMAC-SHA256 signatures (raw body or `<timestamp>.<body>`), optional prefix such as `sha256=`.
- Anti-replay timestamp window and idempotency by event-ID header or body hash.
- Instant `200` response; processing in the background through a cron triggered on arrival.
- Retries with exponential backoff (1, 2, 4… minutes, capped at one hour) up to a configurable limit.
- Concurrency-safe processing (`FOR UPDATE SKIP LOCKED`), per-event savepoints.
- Event log with formatted payload, filtered headers, sender IP and timings; automatic cleanup.

**Quick start**

1. Install the module and open **Webhooks → Configuration → Endpoints**.
2. Create an endpoint, click **Generate secret** and copy the URL into the sending system.
3. Create a **Processing Action** (Python code). The event is `record`:

   ```python
   data = record.get_json()
   env['res.partner'].create({'name': data['name'], 'email': data['email']})
   ```

**Sender side**

```python
import hashlib, hmac, json, requests

body = json.dumps({"name": "Ada Lovelace", "email": "ada@example.com"}).encode()
signature = hmac.new(b"YOUR_SECRET", body, hashlib.sha256).hexdigest()
requests.post("https://your-odoo.com/webhook/my-endpoint", data=body, headers={
    "Content-Type": "application/json",
    "X-Signature": signature,
    "X-Event-Id": "evt_0001",
})
```

Responses: `200 queued`, `200 duplicate`, `401` invalid signature or expired timestamp,
`404` unknown or archived endpoint, `413` body over 2 MB.

**Tests**

```bash
odoo -d test_db -i webhook_inbox --test-enable --test-tags /webhook_inbox --stop-after-init
```

## License

[LGPL-3](LICENSE)
