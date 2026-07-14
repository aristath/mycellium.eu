// swift-tools-version: 6.0
import Foundation
import PackageDescription

let root = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
let rustLib = ProcessInfo.processInfo.environment["MYCELLIUM_RUST_LIB_DIR"]
    ?? root.appendingPathComponent("target/debug").path

let package = Package(
    name: "MycelliumMobile",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [.library(name: "MycelliumMobile", targets: ["MycelliumMobile"])],
    targets: [
        .systemLibrary(
            name: "mycellium_mobileFFI",
            path: "Sources/mycellium_mobileFFI"
        ),
        .target(
            name: "MycelliumMobile",
            dependencies: ["mycellium_mobileFFI"],
            path: "Sources/MycelliumMobile",
            linkerSettings: [
                .unsafeFlags([
                    "-L\(rustLib)", "-lmycellium_mobile",
                    "-Xlinker", "-rpath", "-Xlinker", rustLib,
                ]),
            ]
        ),
        .testTarget(
            name: "MycelliumMobileTests",
            dependencies: ["MycelliumMobile"],
            path: "Tests/MycelliumMobileTests"
        ),
    ]
)
