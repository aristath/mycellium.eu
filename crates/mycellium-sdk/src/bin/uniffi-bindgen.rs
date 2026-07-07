//! The UniFFI bindings-generator entry point.
//!
//! Foreign bindings are generated from the *built* cdylib (library mode), which
//! is why this ships as a crate-local binary rather than relying on a globally
//! installed `uniffi-bindgen` whose version could drift from the `uniffi` crate
//! this library links. Run, after `cargo build`:
//!
//! ```text
//! cargo run --bin uniffi-bindgen -- generate \
//!     --library target/debug/libmycellium_sdk.so \
//!     --language kotlin --out-dir target/bindings/kotlin
//! ```
//!
//! (`--language swift` for Swift.) A clean run proves the exported surface is a
//! valid UniFFI interface.
fn main() {
    uniffi::uniffi_bindgen_main();
}
