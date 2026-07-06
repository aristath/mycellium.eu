# Quickstart

Run Mycellium locally with explicit config files. No shell-level configuration is
required.

## 1. Start The Services

For throwaway local development:

```sh
cargo run -p mycellium-server -- --dev
cargo run -p mycellium-queue -- --dev
```

For durable local services, create JSON files:

```json
{
  "addr": "127.0.0.1:8080",
  "data_dir": "./data/directory",
  "dev_auth": true
}
```

```json
{
  "addr": "127.0.0.1:8090",
  "data_dir": "./data/queue"
}
```

Then run:

```sh
cargo run -p mycellium-server -- --config directory.json
cargo run -p mycellium-queue -- --config queue.json
```

Check them with `curl localhost:8080/health` and `curl localhost:8090/health`.

## 2. Create Two CLI Profiles

Each CLI profile is a JSON file:

```json
{
  "data_dir": "./data/alice",
  "passphrase": "alice dev passphrase",
  "queue": "http://127.0.0.1:8090",
  "name": "Alice"
}
```

```json
{
  "data_dir": "./data/bob",
  "passphrase": "bob dev passphrase",
  "queue": "http://127.0.0.1:8090",
  "name": "Bob"
}
```

Use them explicitly:

```sh
cargo run -p mycellium-cli -- --config alice.client.json identity-new
cargo run -p mycellium-cli -- --config bob.client.json identity-new

cargo run -p mycellium-cli -- --config alice.client.json register alice \
  --addr 127.0.0.1:9001 --directory http://127.0.0.1:8080
cargo run -p mycellium-cli -- --config bob.client.json register bob \
  --addr 127.0.0.1:9002 --directory http://127.0.0.1:8080

cargo run -p mycellium-cli -- --config alice.client.json send bob --as alice \
  --message "hi from the shell" --directory http://127.0.0.1:8080
cargo run -p mycellium-cli -- --config bob.client.json inbox --as bob \
  --directory http://127.0.0.1:8080
```

For a live session, run `listen` for Bob and `chat` for Alice with their
respective config files.

## 3. Run The Browser PWA

```sh
./clients/web/build.sh
python3 -m http.server 8000 --directory clients/web
```

Open `http://localhost:8000/?dir=http://localhost:8080&queue=http://localhost:8090`.

## 4. Run Tests

```sh
cargo test --workspace
cargo test -p mycellium-cli --test e2e
node clients/rust/e2e/pwa.test.mjs
```
