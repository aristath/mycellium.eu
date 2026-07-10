# mycellium-registry

Optional Mycellium account registry.

The registry is not part of message delivery. It does not store, queue, relay,
or route messages.

It provides only account UX:

- email login requests and confirmation
- stable `account_id`
- bearer sessions
- encrypted account-backup blob storage
- signed public-record blob storage
- rate limiting for email login requests

## Run

```sh
MYCELLIUM_REGISTRY_BIND=127.0.0.1:8787 \
MYCELLIUM_REGISTRY_DATA_DIR=.mycellium-registry \
cargo run -p mycellium-registry
```

Defaults:

```text
MYCELLIUM_REGISTRY_BIND=127.0.0.1:8787
MYCELLIUM_REGISTRY_DATA_DIR=.mycellium-registry
```

## API

```text
POST /login/email/request
POST /login/confirm
PUT  /accounts/{account_id}/backup
GET  /accounts/{account_id}/backup
PUT  /accounts/{account_id}/record
GET  /accounts/{account_id}/record
```

Protected endpoints require:

```text
Authorization: Bearer <session_token>
```

`POST /login/email/request` returns `dev_token` for now. That is temporary. The
real version should send that token through the configured email provider.

## Storage

Metadata lives in `redb`.

Opaque account bytes live in filesystem blobs under the configured data
directory.

The registry stores pointers to blobs. Clients create, encrypt, decrypt, and
verify account material locally.
