# Deploy

Mycellium services are configured with JSON files. Shell variables are not part
of the runtime interface.

## Directory

```json
{
  "addr": "0.0.0.0:8080",
  "data_dir": "/var/lib/mycellium/directory",
  "smtp": {
    "host": "smtp.example.com",
    "port": 587,
    "from": "Mycellium <noreply@example.com>",
    "user": "smtp-user",
    "pass": "smtp-password"
  },
  "tls": {
    "cert": "/etc/mycellium/fullchain.pem",
    "key": "/etc/mycellium/privkey.pem"
  },
  "access_log": true
}
```

Run:

```sh
mycellium-server --config /etc/mycellium/directory.json
```

For local development, use `"dev_auth": true` instead of `smtp`.

## Queue

```json
{
  "addr": "0.0.0.0:8090",
  "data_dir": "/var/lib/mycellium/queue",
  "tls": {
    "cert": "/etc/mycellium/fullchain.pem",
    "key": "/etc/mycellium/privkey.pem"
  },
  "access_log": true,
  "push_allow_hosts": []
}
```

Run:

```sh
mycellium-queue --config /etc/mycellium/queue.json
```

## Relay

```json
{
  "addr": "0.0.0.0:8700",
  "data_dir": "/var/lib/mycellium/relay"
}
```

Run:

```sh
mycellium-relay --config /etc/mycellium/relay.json
```

The relay `data_dir` is important because it stores the relay key and keeps the
PeerId stable across restarts.

## Client Profiles

CLI profiles are JSON too:

```json
{
  "data_dir": "/home/alice/.local/share/mycellium",
  "queue": "https://queue.example.com",
  "name": "Alice"
}
```

Run commands with:

```sh
mycellium --config alice.client.json identity-show
```
