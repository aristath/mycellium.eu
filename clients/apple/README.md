# Apple Client

SwiftUI app and SwiftPM SDK integration for Mycellium.

## Build

```sh
./build-rust.sh
swift build
```

`build-rust.sh` builds the host Rust library and generates the Swift binding and
C header consumed by SwiftPM.

## Round-Trip Test

Start fixed-port dev services:

```sh
( cd ../.. && cargo build --release -p mycellium-server -p mycellium-queue )
../../target/release/mycellium-server --config dev-directory.json &
../../target/release/mycellium-queue --config dev-queue.json &
swift test
```

The test uses `http://127.0.0.1:19080` and `http://127.0.0.1:19090`.
