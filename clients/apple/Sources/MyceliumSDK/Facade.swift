// A thin, hand-written facade over the generated UniFFI binding.
//
// Everything the app uses — `MyceliumClient`, the `SecretStore` /
// `EventListener` protocols, and the `Message` / `Conversation` / `Contact` /
// `Account` / `Group` / `EmailVerification` DTOs, the `DeliveryState` /
// `TrustLevel` / `PushPlatform` enums, and the `SdkError` error — is declared
// as `public` in the generated `Generated/mycellium_sdk.swift`, so it is
// re-exported by simply being part of this same `MyceliumSDK` module.
//
// This file exists only to (a) give the target at least one committed source
// file (so the module compiles even before `build-rust.sh` has run, which keeps
// tooling/`swift package describe` happy), and (b) hang small conveniences off
// the generated types without touching the generated file.

import Foundation

/// Package-level metadata for the Apple client's SDK integration layer.
public enum MyceliumSDKInfo {
    /// Matches the SDK boundary this binding was generated against (issues
    /// #68/#69 — the Apple client over the shared UniFFI Swift binding).
    public static let clientPlatform = "apple"
}

public extension Message {
    /// A short leading tick/badge for the message's delivery state, from the
    /// sender's point of view. Empty for inbound (received) messages.
    var deliveryBadge: String {
        guard fromMe else { return "" }
        switch delivery {
        case .queued: return "…"    // parked locally, no device reachable yet
        case .sent: return "✓"      // handed to a recipient device / queue
        case .delivered: return "✓✓" // read/delivery receipt came back
        case .failed: return "⚠︎"    // delivery failed outright
        }
    }
}

public extension TrustLevel {
    /// A one-word label for the peer's verification state, for a contact row.
    var label: String {
        switch self {
        case .unverified: return "Unverified"
        case .pinned: return "Pinned"
        case .verified: return "Verified"
        case .changed: return "Changed!"
        }
    }
}
