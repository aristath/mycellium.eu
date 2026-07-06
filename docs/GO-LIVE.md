# Go-Live Checklist

- [ ] Directory runs from a JSON config with durable `data_dir`.
- [ ] Queue runs from a JSON config with durable `data_dir`.
- [ ] Relay runs from a JSON config with durable `data_dir`, if libp2p relay is used.
- [ ] Directory uses SMTP config, not `dev_auth`.
- [ ] TLS is terminated by the service config or by a reverse proxy.
- [ ] `data_dir` paths are backed up, including queue VAPID key and relay key.
- [ ] Access logs are enabled in JSON config when you need request telemetry.
- [ ] Client profiles point at the production queue URL before registration.
