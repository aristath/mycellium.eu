# mycellium-mobile

Shared Rust boundary for the Android and Apple applications.

UniFFI exposes login, profile publication, connection cards, contacts, safety
numbers, conversations, direct delivery, pending retry, and lifecycle refresh.
Rust owns protocol and encrypted state. Kotlin and Swift own presentation,
lifecycle callbacks, and the platform secure store.

`MobileClient.open` receives an app-private data directory and an optional
opaque 64-byte identity. A newly created or recovered local identity is returned
once so the native shell can immediately place it in Android Keystore or Apple
Keychain. Foreign calls may block and must run away from the UI thread.

The state machine is `NeedsLogin`, `NeedsProfile`, `Ready`, or `Replaced`.
After email confirmation, a new profile chooses its display name and non-unique
handle. Logging in on another device recovers the wallet root, creates fresh
device/message keys, and replaces the old active device. History and pending
messages remain on the old device.

The app should call `refresh_connectivity` and `refresh_device_status` when it
returns to the foreground. A background monitor also checks the active record.
When the OS suspends networking, delivery remains pending on the sender.
