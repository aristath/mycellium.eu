# Production Readiness

The production stance is explicit JSON configuration:

- Durable `data_dir` for directory, queue, and relay.
- SMTP config for directory verification.
- TLS configured directly in service JSON or terminated by a proxy.
- Access logs enabled with `access_log: true` when operationally needed.
- Queue `push_allow_hosts` kept empty unless an operator-owned push distributor
  really needs an internal host.
- Client profiles set the queue URL before registration so records advertise the
  intended mailbox endpoint.

Use `docs/DEPLOY.md` for concrete config examples.
