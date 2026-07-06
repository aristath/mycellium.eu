# mycellium-serve

Shared Axum HTTP runtime for Mycellium services.

Callers pass an explicit `HttpConfig`:

```rust
mycellium_serve::HttpConfig {
    tls: Some(mycellium_serve::TlsConfig {
        cert_path: "/etc/mycellium/fullchain.pem".into(),
        key_path: "/etc/mycellium/privkey.pem".into(),
    }),
    access_log: true,
}
```

The runtime adds `/health`, `/metrics`, CORS, body limits, redacted request
logging, TLS when configured, and graceful shutdown.
