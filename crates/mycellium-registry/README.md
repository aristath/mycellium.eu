# mycellium-registry

Optional Mycellium account registry.

The registry is not part of message delivery. It does not store, queue, relay,
or route messages.

It provides only account UX:

- email login requests and confirmation
- stable `account_id`
- bearer sessions
- registry-encrypted, write-once identity recovery
- encrypted account-backup blob storage
- signed public-record blob storage
- rate limiting for email login requests

## Run

```sh
MYCELLIUM_REGISTRY_BIND=127.0.0.1:8787 \
MYCELLIUM_REGISTRY_DATA_DIR=.mycellium-registry \
MYCELLIUM_REGISTRY_RECOVERY_KEY=<64 hexadecimal characters> \
MYCELLIUM_REGISTRY_EMAIL_TRANSPORT=log \
cargo run -p mycellium-registry
```

Defaults:

```text
MYCELLIUM_REGISTRY_BIND=127.0.0.1:8787
MYCELLIUM_REGISTRY_DATA_DIR=.mycellium-registry
MYCELLIUM_REGISTRY_RECOVERY_KEY=<64 hexadecimal characters>
```

Email transport is explicit. Use `log` for local development:

```text
MYCELLIUM_REGISTRY_EMAIL_TRANSPORT=log
```

Use Brevo's HTTPS transactional email API when SMTP egress is unavailable:

```text
MYCELLIUM_REGISTRY_EMAIL_TRANSPORT=brevo
MYCELLIUM_REGISTRY_EMAIL_FROM=Mycellium <login@example.com>
MYCELLIUM_REGISTRY_BREVO_API_KEY=<brevo api key>
```

Use generic SMTP for production:

```text
MYCELLIUM_REGISTRY_EMAIL_TRANSPORT=smtp
MYCELLIUM_REGISTRY_EMAIL_FROM=Mycellium <login@example.com>
MYCELLIUM_REGISTRY_SMTP_HOST=smtp-relay.brevo.com
MYCELLIUM_REGISTRY_SMTP_PORT=587
MYCELLIUM_REGISTRY_SMTP_USERNAME=<smtp username>
MYCELLIUM_REGISTRY_SMTP_PASSWORD=<smtp password>
```

Brevo uses HTTPS on port 443. Generic SMTP usually needs outbound port 587.

Optional:

```text
MYCELLIUM_REGISTRY_EMAIL_SUBJECT=Your Mycellium login code
MYCELLIUM_REGISTRY_LOGIN_URL_TEMPLATE=mycellium://login?token={token}
MYCELLIUM_REGISTRY_BREVO_ENDPOINT=https://api.brevo.com/v3/smtp/email
```

## API

```text
POST /login/email/request
POST /login/confirm
PUT  /accounts/{account_id}/backup
GET  /accounts/{account_id}/backup
PUT  /accounts/{account_id}/recovery
GET  /accounts/{account_id}/recovery
PUT  /accounts/{account_id}/record
GET  /accounts/{account_id}/record
```

Protected endpoints require:

```text
Authorization: Bearer <session_token>
```

`POST /login/email/request` returns `202 Accepted` and sends the one-time token
through the configured email sender. The token is not returned in the HTTP
response.

Current upload limits:

```text
backup: 16 MiB
public record: 1 MiB
```

## Storage

Metadata lives in `redb`.

Opaque account bytes live in filesystem blobs under the configured data
directory.

The registry stores pointers to blobs. Generic backup blobs remain opaque and
client-encrypted. Recovery is deliberately separate: the authenticated client
sends the 32-byte wallet root over HTTPS, and the registry seals it with
`MYCELLIUM_REGISTRY_RECOVERY_KEY` before writing it. Recovery is write-once and
public records must belong to that identity.

The recovery key must be kept outside the data directory and backed up. Losing
it makes recovery blobs unreadable; exposing it allows identities to be
recovered, but does not expose message history or device message keys.
