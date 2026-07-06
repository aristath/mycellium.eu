# mycellium-queue

A per-recipient, wallet-keyed store-and-forward mailbox. It stores opaque
end-to-end encrypted blobs and cannot read message contents.

## Run

```sh
mycellium-queue --dev
mycellium-queue --config queue.json
```

Config is JSON:

```json
{
  "addr": "127.0.0.1:8090",
  "data_dir": "./data/queue",
  "access_log": false,
  "push_allow_hosts": []
}
```

Use `tls.cert` and `tls.key` when the queue terminates HTTPS itself:

```json
{
  "addr": "0.0.0.0:8090",
  "data_dir": "/var/lib/mycellium/queue",
  "tls": {
    "cert": "/etc/mycellium/fullchain.pem",
    "key": "/etc/mycellium/privkey.pem"
  },
  "access_log": true,
  "push_allow_hosts": ["ntfy.internal.example:443"]
}
```

## API

The queue exposes `/health`, `/login/challenge`, `/login/verify`,
`/mailbox/{wallet}/{slot}`, `/push/key`, `/push/subscribe`,
`/push/unsubscribe`, `/pair/{rid}`, and `/metrics`.

Persistent queues keep mailboxes, push subscriptions, and the VAPID key in
`data_dir`.
