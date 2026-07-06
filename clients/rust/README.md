# mycellium-client

Local Rust/PWA host for Mycellium.

```sh
mycellium-client --port 8800 \
  --directory http://127.0.0.1:8080 \
  --queue http://127.0.0.1:8090 \
  --data-dir .mycellium
```

The app configures the engine in-process from these flags and stores a generated
device key inside `--data-dir` for passwordless local use.
