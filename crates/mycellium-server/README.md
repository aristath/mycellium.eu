# mycellium-server

The deployable directory server. It is a thin binary shell around
`mycellium-directory`.

## Run

```sh
mycellium-server --dev
mycellium-server --config directory.json
```

Config is JSON:

```json
{
  "addr": "127.0.0.1:8080",
  "data_dir": "./data/directory",
  "dev_auth": true,
  "access_log": false
}
```

Production email verification uses SMTP instead of `dev_auth`:

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

Routes include `/health`, `/login/challenge`, `/login/verify`, `/auth/start`,
`/auth/confirm`, `/auth/status`, `/records/{handle}`, `/presence/{handle}`, and
`/metrics`.
