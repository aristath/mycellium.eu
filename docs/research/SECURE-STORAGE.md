# Secure storage for the account root secret — design note

*Design research for issue [#65](https://github.com/aristath/mycellium.eu/issues/65)
(OS secure storage for the native SDK; native-client tracker
[#74](https://github.com/aristath/mycellium.eu/issues/74)). The **abstraction, a
safe passphrase default, and the migration off the plaintext sidecar ship now**
in [`crates/mycellium-sdk/src/secrets.rs`](../../crates/mycellium-sdk/src/secrets.rs);
this note designs the **per-OS adapters** each platform app implements against it.*

> **Status:** part-shipped, part-design. The `SecretStore` seam,
> `PassphraseFileSecretStore` (Argon2id + ChaCha20-Poly1305), the dev-only
> `PlaintextFileSecretStore`, and the `identity.json` → store migration are code
> today. The Keychain / Keystore / DPAPI / libsecret adapters below are the
> remaining per-platform work (the app owns them; the SDK never links an OS
> keystore itself). Read alongside the code it builds on —
> [`secrets.rs`](../../crates/mycellium-sdk/src/secrets.rs),
> [`client.rs` `load_or_create_identity`](../../crates/mycellium-sdk/src/client.rs),
> [`mycellium-storage/src/store.rs`](../../crates/mycellium-storage/src/store.rs)
> (the CLI's proven at-rest sealing we reuse) — and the docs it cross-cuts:
> [`AUDIT-BRIEF.md` §2.14](../AUDIT-BRIEF.md), [`SECURITY.md`](../SECURITY.md),
> [`NATIVE-CLIENTS.md`](../NATIVE-CLIENTS.md),
> [`PRODUCTION-READINESS.md` §N2](../PRODUCTION-READINESS.md).

## 0. One-line framing (the honest version)

The account is a 32-byte **wallet secret** plus this device's 32-byte **device
seed** — no seed phrase (recovery is email re-binding, [#6](https://github.com/aristath/mycellium.eu/issues/6)).
That root key *is* the account: whoever holds it can impersonate the account and
decrypt everything the [`FileStore`](../../crates/mycellium-storage/src/filestore.rs)
holds, because the FileStore is keyed *from* the identity via HKDF and therefore
**cannot hold its own key**. So the root key has to live somewhere outside the
encrypted store, and *where* is the one honest security decision this note is
about.

Until now the SDK wrote it to `data_dir/identity.json` as plaintext JSON,
`chmod 0600` best-effort on Unix only ([`AUDIT-BRIEF.md` §2.14](../AUDIT-BRIEF.md)).
That is confidentiality-by-filesystem-permission and nothing more: any process
running as the user, any backup that copies the file, any forensic image reads
the account key in the clear. #65 replaces it with a platform-chosen store behind
one small trait.

**State the residual plainly, never claim "unstealable".** An OS keystore raises
the bar from *"read a file"* to *"defeat the platform's key protection"* — often
hardware-backed (Secure Enclave, StrongBox/TEE, TPM). It does **not** make the
key unstealable on a **rooted/jailbroken device**, against an attacker who can run
code *as the app while the device is unlocked*, or against a **backup** that
captures wrapped material the same OS will later unwrap. The claim is precise:
*at-rest confidentiality against offline/file-level access and other apps* — not
*invulnerability against a compromised runtime*.

---

## 1. The seam: `SecretStore`

The whole abstraction is three methods (in
[`secrets.rs`](../../crates/mycellium-sdk/src/secrets.rs), exported across UniFFI
as a `callback_interface` so Kotlin/Swift implement it):

```rust
#[uniffi::export(callback_interface)]
pub trait SecretStore: Send + Sync {
    fn store(&self, key: String, secret: Vec<u8>) -> Result<(), SdkError>;
    fn load(&self, key: String) -> Result<Option<Vec<u8>>, SdkError>;
    fn delete(&self, key: String) -> Result<(), SdkError>;
}
```

- The SDK stores **only small, high-value material** through it: today the
  identity secret under the key `"identity"`; later, push tokens
  ([#71](https://github.com/aristath/mycellium.eu/issues/71)) under their own keys.
  The bulk store (history, contacts, groups, config) stays in the encrypted
  `FileStore` and never goes through here.
- `load` of an absent key is `Ok(None)`. **Every other failure is an error**, and
  the SDK treats it as fatal — see §6, fail-closed.
- The app passes its implementation to
  `MyceliumClient::new_with_secret_store(data_dir, secrets)`. The convenience
  `MyceliumClient::new(data_dir)` exists for dev/tests only and wires the
  plaintext file store, with a doc-comment that production apps MUST supply an
  OS-backed store.

**Two shipped Rust defaults** (honest, because with neither an OS keystore nor a
passphrase there is nothing to encrypt the key *with*):

| Default | Protection | Use |
|---|---|---|
| `PassphraseFileSecretStore` | Argon2id-derived key + ChaCha20-Poly1305, per-secret random salt+nonce, `0600` file — the same construction as the CLI's [`store.rs`](../../crates/mycellium-storage/src/store.rs) | headless / server / CI where a passphrase (or operator secret) exists but no keystore does |
| `PlaintextFileSecretStore` | `0600` file, **no encryption** — explicitly named, doc-flagged dev/fallback only | local dev, tests, and the migration landing spot |

---

## 2. Per-OS adapter mapping

The recurring pattern across every real OS keystore: the keystore either **stores
the ~64 bytes directly** (small-secret path) or **holds a non-exportable wrapping
key** the app uses to seal a blob it keeps in app storage (envelope path). Both
map onto the same trait — `store`/`load`/`delete` — and both must fail closed.

### 2.1 Android — Keystore (`AndroidKeyStore`)

- **What's stored where.** Android Keystore does not store arbitrary secrets well;
  it stores **keys**. Use the *envelope* path: generate a non-exportable AES-GCM
  (or RSA/EC-wrap) key in `AndroidKeyStore` — hardware-backed via TEE/**StrongBox**
  where available — and use it to wrap the ~64-byte identity secret. Persist the
  wrapped blob (+ IV) in app-private storage (`EncryptedSharedPreferences` or a
  file in `filesDir`, which is already app-sandboxed). `store` = wrap + write;
  `load` = read + unwrap; `delete` = delete key + blob. (Jetpack Security's
  `EncryptedFile`/`MasterKey` is exactly this pattern pre-packaged.)
- **Wrapping key vs. stored secret.** Wrapping key (hardware-held, non-exportable);
  the secret is the wrapped blob in app storage.
- **Residual limits.** A rooted device with the screen unlocked can ask the
  Keystore to unwrap (unless key use is gated on user auth — see below). StrongBox
  raises cost; TEE-only is weaker. Setting `setUserAuthenticationRequired(true)`
  binds unwrap to a biometric/PIN prompt (good for a "lock the app" UX). Full-disk
  `allowBackup="false"` and no cloud backup of the blob (see §5).

### 2.2 iOS / macOS — Keychain (`GenericPassword`)

- **What's stored where.** Small-secret path: store the ~64 bytes **directly** as a
  `kSecClassGenericPassword` item. Use a stable `kSecAttrService`
  (e.g. `eu.mycellium.identity`) + `kSecAttrAccount` = the `key`. On the Secure
  Enclave-backed devices the item's protection class is the real control.
- **Attributes that matter (set them, don't default).**
  - `kSecAttrAccessible = kSecAttrAccessibleWhenUnlockedThisDeviceOnly` — readable
    only while the device is unlocked, and (`ThisDeviceOnly`) **never migrated to a
    new device or iCloud Keychain backup** (so the raw secret can't leave the
    device via restore — §5).
  - `kSecAttrAccessGroup` = a shared app-group id if the app + its extensions
    (share/notification-service for [#71](https://github.com/aristath/mycellium.eu/issues/71))
    must read the same identity; otherwise omit for the tightest scope.
  - Optionally `SecAccessControl` with `.biometryCurrentSet`/`.userPresence` to gate
    reads on Face/Touch ID.
- **Wrapping key vs. stored secret.** Stored directly (Keychain is itself
  hardware-protected); no app-side envelope needed.
- **Residual limits.** A jailbroken device or a runtime attacker in-process while
  unlocked can request the item. `WhenUnlockedThisDeviceOnly` blocks locked-state
  reads and cross-device restore, but not a live compromised app.

### 2.3 Windows — DPAPI (+ optional Credential Manager)

- **What's stored where.** Envelope path: `CryptProtectData` (DPAPI,
  `CRYPTPROTECT_LOCAL_MACHINE` *off* → per-user) seals the ~64-byte secret to the
  **current user's** login credentials; write the protected blob to
  `%LOCALAPPDATA%\Mycellium\`. `load` = read + `CryptUnprotectData`. Optionally use
  **Credential Manager** (`CredWrite`/`CredRead`, `CRED_TYPE_GENERIC`) as the store
  location instead of a file; the confidentiality still comes from DPAPI/user
  profile. For a hardware-bound variant, wrap with a **CNG key in the TPM**
  (Platform Crypto Provider) and store the wrapped blob.
- **Wrapping key vs. stored secret.** DPAPI's per-user master key is the wrapping
  key (OS-held, derived from the user's credentials); the secret is the protected
  blob.
- **Residual limits.** Any code running **as that user** can call
  `CryptUnprotectData` — DPAPI protects against *other users* and *offline disk
  access*, not same-user malware. Roaming profiles/backups that carry the DPAPI
  master key can unwrap elsewhere; TPM-bound CNG keys resist that.

### 2.4 Linux — Secret Service / libsecret (+ headless fallback)

- **What's stored where.** Small-secret path via the **Secret Service API**
  (libsecret → GNOME Keyring / KWallet): store the ~64 bytes as a labelled secret
  item keyed by attributes (`service=eu.mycellium`, `key=identity`). The desktop's
  keyring is unlocked with the login password (often auto-unlocked at login via
  PAM).
- **Wrapping key vs. stored secret.** Stored directly; the keyring daemon holds the
  encryption key derived from the login secret.
- **Residual limits.** Requires a running keyring daemon and a session bus — **not
  present on headless servers, containers, or CI**. When absent, the app **must not
  silently fall back to plaintext**; it falls back to the shipped
  **`PassphraseFileSecretStore`** (Argon2id + ChaCha20-Poly1305), documented as the
  headless path in [`secrets.rs`](../../crates/mycellium-sdk/src/secrets.rs). An
  auto-unlocked keyring is only as strong as the login session; a same-user
  attacker in the unlocked session can read items.

### 2.5 Summary table

| OS | Mechanism | Direct vs. wrapping | Hardware root (typical) | Key residual |
|---|---|---|---|---|
| Android | Keystore + app storage | Wrapping key | TEE / StrongBox | Rooted + unlocked; backup of blob |
| iOS/macOS | Keychain GenericPassword | Direct | Secure Enclave | Jailbroken + unlocked; in-proc while unlocked |
| Windows | DPAPI (opt. CredMan / TPM CNG) | Wrapping key | TPM (if CNG) | Same-user code; roamed master key |
| Linux | Secret Service / libsecret | Direct | none (software keyring) | Unlocked session; **no daemon → passphrase fallback** |
| headless | `PassphraseFileSecretStore` | Wrapping key (Argon2id) | none | Passphrase strength; offline guessing |

---

## 3. Load / create / migrate flow (shipped)

`load_or_create_identity` in [`client.rs`](../../crates/mycellium-sdk/src/client.rs)
runs the same three-step logic regardless of which `SecretStore` backs it:

1. `secrets.load("identity")` → `Some(bytes)` ⇒ decode and use it.
2. Else if a legacy plaintext `data_dir/identity.json` sidecar exists ⇒ **import it
   into the store** (`secrets.store("identity", bytes)` — same JSON form, byte-for-
   byte), **delete the sidecar**, use it. This upgrades pre-#65 SDK data cleanly the
   first time an app opens it with an OS-backed store.
3. Else generate a fresh identity and `secrets.store("identity", …)`.

Device pairing ([`adopt_from_payload`](../../crates/mycellium-sdk/src/client.rs))
re-stores the adopted account key the same way. The wire form is unchanged, so the
migration is transparent and reversible in shape (though after step 2 the plaintext
copy is gone by design).

---

## 4. What crosses the boundary

The SDK never returns raw key material across the UniFFI boundary except the
**public** wallet address (a stable, shareable account id). `SecretStore` methods
move opaque `Vec<u8>` the app persists but should not inspect, log, or transmit.
The app-side adapter must treat the bytes as sensitive: no logging, no analytics,
zeroize buffers where the platform allows.

---

## 5. Backup / restore must not export raw secrets

This is a hard rule, not a preference:

- **iOS/macOS:** `…ThisDeviceOnly` protection classes keep the item out of iCloud
  Keychain and encrypted backups. Do **not** use a non-`ThisDeviceOnly` class for
  the identity.
- **Android:** exclude the wrapped blob from Auto Backup / Google backup
  (`android:allowBackup="false"` or `dataExtractionRules`/`fullBackupContent`). The
  Keystore key itself is already non-exportable; the point is not to ship the
  wrapped blob to a place a *different* device's OS could later unwrap.
- **Windows/Linux:** don't roam the DPAPI master key / keyring to another machine
  and expect it *not* to unwrap there — TPM/keyring binding is what prevents it.
- **The account-level answer:** losing the device (and thus its at-rest key) is
  **recoverable without ever exporting the raw secret** — the account is re-bound to
  the handle from a fresh device via **email verification**
  ([#6](https://github.com/aristath/mycellium.eu/issues/6)), and existing SDK data
  restores from the store [`export_backup`](../../crates/mycellium-sdk/src/client.rs),
  which is encrypted under the account storage key and **contains no identity
  secret** (the `secrets/` material is deliberately outside the backup set). So a
  backup can be portable *without* carrying the root key.

---

## 6. Storage failures must fail closed

If `store` cannot durably persist, or `load` returns an error (I/O, decrypt/tag
failure, keystore unavailable, user cancelled a biometric prompt), the SDK
**surfaces a clear `SdkError` and refuses to proceed** — it never falls back to a
weaker store, never fabricates a fresh identity that would silently orphan the
account, and never continues with a key it couldn't verify. Concretely:

- `PassphraseFileSecretStore::load` maps a wrong passphrase / AEAD tag failure to
  `SdkError::Crypto("wrong passphrase or corrupt secret")` — it does **not** return
  `Ok(None)` (which would look like "no identity" and trigger key generation).
- A keystore-unavailable condition (locked device, absent Linux daemon) is an
  error the app resolves (prompt to unlock, or configure the passphrase fallback),
  not a silent downgrade.
- Only a genuinely absent key is `Ok(None)`.

Tests in [`crates/mycellium-sdk/tests/sdk.rs`](../../crates/mycellium-sdk/tests/sdk.rs)
pin this: a `MockSecretStore` drives the SDK end-to-end (identity persists across a
reopen through the store), `PassphraseFileSecretStore` round-trips and **fails
closed on the wrong passphrase**, and the legacy-sidecar migration imports then
removes `identity.json`.

---

## 7. Cross-references

- **This issue:** [#65](https://github.com/aristath/mycellium.eu/issues/65) — OS
  secure storage for the account key; [`PRODUCTION-READINESS.md` §N2](../PRODUCTION-READINESS.md).
- **The boundary this lives behind:** [#64](https://github.com/aristath/mycellium.eu/issues/64)
  (native SDK / UniFFI boundary — the `SecretStore` seam is part of that stable
  surface); the interim plaintext sidecar is called out in
  [`AUDIT-BRIEF.md` §2.14](../AUDIT-BRIEF.md).
- **Also sensitive → same store:** [#71](https://github.com/aristath/mycellium.eu/issues/71)
  (native push tokens are device-sensitive material; they go through `SecretStore`
  under their own keys, per [`NATIVE-PUSH.md`](NATIVE-PUSH.md)).
- **Apps that implement the adapters:** [#67](https://github.com/aristath/mycellium.eu/issues/67)
  (Android/Keystore), [#68](https://github.com/aristath/mycellium.eu/issues/68)
  (iOS/Keychain), [#69](https://github.com/aristath/mycellium.eu/issues/69)
  (macOS/Keychain), [#70](https://github.com/aristath/mycellium.eu/issues/70)
  (Linux/Secret Service), [#72](https://github.com/aristath/mycellium.eu/issues/72)
  (Windows/DPAPI); tracker [#74](https://github.com/aristath/mycellium.eu/issues/74).
- **Recovery model (why losing the at-rest key is survivable):**
  [#6](https://github.com/aristath/mycellium.eu/issues/6) (email re-binding, no seed
  phrase); the at-rest sealing we reuse is
  [`mycellium-storage/src/store.rs`](../../crates/mycellium-storage/src/store.rs).
- **Audit brief & threat model:** [`AUDIT-BRIEF.md`](../AUDIT-BRIEF.md),
  [`SECURITY.md`](../SECURITY.md).
