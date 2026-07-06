# mycellium-directory

The untrusted signed-record directory.

## Serving

Embedders pass explicit `ServeConfig`:

```rust
mycellium_directory::serve("127.0.0.1:8080", mycellium_directory::ServeConfig::dev()).await?;
```

Durable and SMTP-backed serving uses:

```rust
mycellium_directory::ServeConfig {
    data_dir: Some("./data/directory".into()),
    auth: mycellium_directory::AuthConfig::Smtp(mycellium_directory::SmtpConfig {
        host: "smtp.example.com".into(),
        port: 587,
        from: "Mycellium <noreply@example.com>".into(),
        user: None,
        pass: None,
    }),
    http: mycellium_serve::HttpConfig::default(),
}
```

The deployable binary reads the same shape from `mycellium-server --config`.
