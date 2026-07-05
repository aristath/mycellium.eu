# Deploying Mycellium

The public services are the **directory** (`mycellium-server`) and the **queue**
(`mycellium-queue`). Both are single static binaries that serve HTTP(S) and hold
their own durable state. Neither ever sees message plaintext — only names,
records, and sealed store-and-forward blobs.

## Environment

Both binaries read the same variables:

| Variable | Purpose | Default |
|---|---|---|
| `MYCELLIUM_DATA` | Data **directory**. Each service creates its own file inside (`directory.redb` / `queue.redb`). | unset → in-memory (dev only). **Set = durable intent: if the store can't be opened, startup fails rather than silently running in-memory.** |
| `MYCELLIUM_TLS_CERT` / `MYCELLIUM_TLS_KEY` | PEM cert + key → serve HTTPS directly. | unset → HTTP (put a proxy in front) |
| `MYCELLIUM_LOG` | `1` → structured JSON access log per request on stdout. | unset → only 5xx are logged |

Directory only (signup email — see below):

| Variable | Purpose |
|---|---|
| `MYCELLIUM_SMTP_HOST` | SMTP server. **Production requires this.** |
| `MYCELLIUM_SMTP_PORT` | 587 (STARTTLS, default) or 465 (implicit TLS) |
| `MYCELLIUM_SMTP_FROM` | e.g. `Mycellium <noreply@yourdomain>` |
| `MYCELLIUM_SMTP_USER` / `MYCELLIUM_SMTP_PASS` | SMTP auth (optional) |
| `MYCELLIUM_DEV_AUTH` | `1` → **development** mode: the verification code is logged and returned in the API response instead of emailed. For local dev only. |

> **Privacy:** use your **own** SMTP server. Never a US SMS/email gateway.
>
> **Fail-closed:** the directory **refuses to start** unless *either* `MYCELLIUM_SMTP_HOST`
> is configured *or* `MYCELLIUM_DEV_AUTH=1` is set explicitly. A missing SMTP config no
> longer silently drops to the code-logging dev path — a misconfiguration is a startup
> error, not a quiet weakening of auth.

## TLS

HTTPS is required off `localhost` — service workers, Web Push, and PWA install
all refuse to run over plain HTTP.

### Recommended: reverse proxy (automatic HTTPS)

Run the services on plain HTTP bound to localhost and let [Caddy](https://caddyserver.com)
terminate TLS with automatic Let's Encrypt certificates:

```
# Caddyfile
directory.example.com {
    reverse_proxy 127.0.0.1:8600
}
queue.example.com {
    reverse_proxy 127.0.0.1:8700
}
```

```sh
export MYCELLIUM_DATA=/var/lib/mycellium
export MYCELLIUM_SMTP_HOST=smtp.yourdomain  MYCELLIUM_SMTP_FROM='Mycellium <noreply@yourdomain>'
mycellium-server --addr 127.0.0.1:8600 &
mycellium-queue  --addr 127.0.0.1:8700 &
caddy run
```

Caddy handles certificate issuance/renewal, HTTP/2, and redirects — nothing to
manage in the app.

### Alternative: native TLS

For a single-box deploy without a proxy, point the services at PEM files — TLS is
terminated in-process by **rustls** (a pure-Rust, memory-safe stack; no system
OpenSSL needed):

```sh
export MYCELLIUM_TLS_CERT=/etc/mycellium/cert.pem
export MYCELLIUM_TLS_KEY=/etc/mycellium/key.pem
mycellium-server --addr 0.0.0.0:443
```

You are then responsible for certificate renewal (e.g. a certbot cron). On
`SIGTERM`/`SIGINT` the service shuts down gracefully — in-flight requests drain
(up to 10s) and the durable store closes cleanly — so a rolling restart drops no
work.

## Observability

- **`GET /health`** — liveness (returns `"ok"`).
- **`GET /metrics`** — Prometheus text: `mycellium_requests_total`,
  `mycellium_client_errors_total` (4xx), `mycellium_server_errors_total` (5xx),
  each labelled `service="directory"|"queue"`. Point Prometheus at both.
- **Access logs** — set `MYCELLIUM_LOG=1` for a JSON line per request
  (`{t, svc, method, path, status, ms}`). Paths carry only opaque ids, never
  plaintext names or emails.

## Serving the browser PWA

The web client ([`clients/web`](../clients/web)) is **static files** — no app server.

```sh
./clients/web/build.sh          # compile mycellium-wasm → clients/web/pkg/
```

Then serve the `clients/web/` directory as a static site over **HTTPS** (service
workers, Web Push, and install all refuse plain HTTP off localhost). Any static host
works; with Caddy:

```
app.example.com {
    root * /srv/mycellium/clients/web
    file_server
    try_files {path} /index.html
}
```

- Ship `index.html`, `worker.js`, `sw.js`, `manifest.json`, `icon.svg`, and the
  generated `pkg/` (serve `.wasm` as `application/wasm`).
- Clients discover the services from the URL query on first load —
  `https://app.example.com/?dir=https://directory.example.com&queue=https://queue.example.com`
  — or from the in-app Setup screen; the choice is remembered in `localStorage`.
- The directory and queue already send permissive CORS, so a browser on a different
  origin can call them directly.

## Web Push

The queue implements contentless Web Push (VAPID) to wake a closed PWA. Its VAPID
keypair is generated once and **persisted to `MYCELLIUM_DATA/vapid.key`** (0600), so
the public key browsers subscribed against survives restarts — set `MYCELLIUM_DATA`
in production or every restart invalidates all existing push subscriptions. No extra
configuration is needed; `GET /push/key` serves the public key to clients.

## Recipient-owned queues

**The queue is chosen by the recipient, not by the network.** This is a core
architectural point, and it's why the directory and the queue are separate
services with separate trust.

- **Directory vs queue.** The **directory** is the one shared name registry
  (`handle → signed record`) — everyone uses the same one to find each other. The
  **queue** is a per-recipient store-and-forward mailbox, and *which* queue is
  yours is a field in **your own signed record**. You publish your queue's URL;
  senders read it from your record and deposit there. Changing it is a record
  update you sign — no one else decides where your mail lands (see #53 for
  rotation, #54 for multiple endpoints).

- **Three ways to run a queue** — the protocol is identical; only who operates it
  differs:
  - **Self-hosted.** Run `mycellium-queue` on your own box/VPS, point your record
    at it (`MYCELLIUM_QUEUE=https://queue.you.example` when you register). Maximum
    control; you carry the ops.
  - **Community / cooperative.** A collective runs one queue for its members —
    a co-op, a server community, a family. Shared ops, shared trust boundary.
  - **Provider-hosted.** A provider offers queues as a service; you point your
    record at theirs. Lowest effort; you trust them with the metadata below.

- **What a queue operator can and cannot see.** A queue never sees message
  **content** (blobs are end-to-end sealed). It **does** see, for mail it handles:
  the **sender** and **recipient** wallets (deposits are sender-authenticated),
  the device slot, deposit/collection **timing**, approximate blob **size**, and
  your **queue depth**. So the operator you choose learns your who-talks-to-whom
  metadata for mail routed through them — run or pick one accordingly. Full detail
  in [`SECURITY.md`](SECURITY.md#the-queue-observes).

- **Operator responsibilities.** A queue holds only opaque blobs + push
  subscriptions, but it is still infrastructure: terminate **TLS** (above), set
  `MYCELLIUM_DATA` for **durable** state (it fails closed if the store can't open),
  plan **backups** and **retention** (undelivered mail is capped per mailbox and
  dropped past its bounds), **monitor** availability (a down queue withholds mail),
  and handle **abuse** (deposits are rate-limited per sender wallet). A queue can
  be operated entirely independently of the directory.

## Scaling notes

- The **directory** is read-mostly and designed to be cloned behind a load
  balancer; the durable store moves to Postgres for multi-node (roadmap T0.1).
- The **queue** is per-recipient store-and-forward; shard by recipient wallet
  when one node isn't enough.
- Both serve on an async runtime (**axum + hyper + tokio**, via the shared
  `mycellium-serve` crate), so a single node handles many concurrent connections
  on a small thread pool; validate under load before a large launch (T2.4).

See [PRODUCTION-READINESS.md](PRODUCTION-READINESS.md) for what's done and what's
left.
