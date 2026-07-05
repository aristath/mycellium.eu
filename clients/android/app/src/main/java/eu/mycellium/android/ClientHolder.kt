package eu.mycellium.android

import android.content.Context
import uniffi.mycellium_sdk.MyceliumClient

/**
 * Process-wide holder for the one [MyceliumClient]. The client is a stateful
 * handle to this account on this device; the app builds exactly one and shares
 * it (the Rust object guards its own interior state with a Mutex, so it is safe
 * to call from any thread).
 *
 * The client is built with [MyceliumClient.newWithSecretStore] — the production
 * constructor — backed by [AndroidKeystoreSecretStore]. The plaintext dev
 * constructor `MyceliumClient(dataDir)` is deliberately never used.
 *
 * [get] BLOCKS: `newWithSecretStore` opens the encrypted store and touches the
 * Keystore. Call it off the main thread (the ViewModel builds it on
 * `Dispatchers.IO`).
 */
object ClientHolder {

    @Volatile
    private var client: MyceliumClient? = null

    fun get(context: Context): MyceliumClient {
        client?.let { return it }
        synchronized(this) {
            client?.let { return it }
            val app = context.applicationContext
            val built = MyceliumClient.newWithSecretStore(
                // data_dir: app-private, sandboxed storage for the encrypted store.
                app.filesDir.path,
                // The OS-keystore-backed secret store for the account root key (#65).
                AndroidKeystoreSecretStore(app),
            )
            client = built
            return built
        }
    }
}
