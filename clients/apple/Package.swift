// swift-tools-version:5.9
//
// Mycellium — Apple (iOS + macOS) client package (issues #68 + #69).
//
// A thin SwiftUI UI over the `mycellium-sdk` UniFFI **Swift** bindings. No
// protocol, crypto, storage, or network logic lives here — the app renders SDK
// state and forwards user intent; everything else is behind the SDK boundary.
//
// This SwiftPM package builds and tests the SDK-integration *core* (the
// generated binding + a thin facade + the Keychain/file secret stores + a real
// messaging round-trip test). It links the host `libmycellium_sdk.so` on Linux,
// so `swift build` / `swift test` run here (CI-friendly, no Mac needed).
//
// The SwiftUI app itself lives under `App/` and is DELIBERATELY OUTSIDE the
// SwiftPM targets — it imports UIKit/SwiftUI/Security, which do not exist on
// Linux. A Mac developer builds it with Xcode (see README.md and App/project.yml).
//
// Before `swift build`, run `./build-rust.sh` once: it builds the `.so` and
// generates the two build artifacts this package consumes (both gitignored):
//   - Sources/MyceliumSDK/Generated/mycellium_sdk.swift   (the Swift binding)
//   - Sources/mycellium_sdkFFI/mycellium_sdkFFI.h         (the C ABI header)

import Foundation
import PackageDescription

// Locate the host Rust `.so` (produced by `build-rust.sh` / `cargo build`).
// Defaults to `<repo>/target/debug` relative to this manifest; override with
// MYCELLIUM_RUST_LIB_DIR (e.g. `target/release`, or an xcframework staging dir).
let manifestDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let defaultRustLibDir = manifestDir
    .deletingLastPathComponent()          // clients/
    .deletingLastPathComponent()          // <repo root>
    .appendingPathComponent("target")
    .appendingPathComponent("debug")
    .path
let rustLibDir = ProcessInfo.processInfo.environment["MYCELLIUM_RUST_LIB_DIR"] ?? defaultRustLibDir

// Link the host `.so` into any product (the test bundle) that pulls in
// MyceliumSDK, and embed an rpath so the test binary finds it at runtime
// without LD_LIBRARY_PATH. `unsafeFlags` is fine: this is a leaf app package,
// never consumed as a dependency by another package.
let sdkLinkerSettings: [LinkerSetting] = [
    .unsafeFlags([
        "-L\(rustLibDir)",
        "-lmycellium_sdk",
        "-Xlinker", "-rpath", "-Xlinker", rustLibDir,
    ])
]

let package = Package(
    name: "Mycellium",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(name: "MyceliumSDK", targets: ["MyceliumSDK"]),
        .library(name: "MyceliumSecrets", targets: ["MyceliumSecrets"]),
    ],
    targets: [
        // The C ABI: the generated UniFFI header + a committed modulemap. The
        // module name (`mycellium_sdkFFI`) is what the generated Swift imports.
        .systemLibrary(
            name: "mycellium_sdkFFI",
            path: "Sources/mycellium_sdkFFI"
        ),

        // The Swift binding (generated into Generated/) + a thin facade. Links
        // the Rust `.so` via the linker settings above.
        .target(
            name: "MyceliumSDK",
            dependencies: ["mycellium_sdkFFI"],
            path: "Sources/MyceliumSDK",
            linkerSettings: sdkLinkerSettings
        ),

        // The `SecretStore` adapters: Keychain on Apple, a file fallback on
        // Linux/dev. Pure Swift over the SDK's `SecretStore` protocol.
        .target(
            name: "MyceliumSecrets",
            dependencies: ["MyceliumSDK"],
            path: "Sources/MyceliumSecrets"
        ),

        // The real messaging round-trip test — runs on Linux against a live
        // dev directory + queue (see build-rust.sh / README for how to start
        // them; ports via MYCELLIUM_DIR_URL / MYCELLIUM_QUEUE_URL).
        .testTarget(
            name: "MyceliumSDKTests",
            dependencies: ["MyceliumSDK", "MyceliumSecrets"],
            path: "Tests/MyceliumSDKTests",
            linkerSettings: sdkLinkerSettings
        ),
    ]
)
