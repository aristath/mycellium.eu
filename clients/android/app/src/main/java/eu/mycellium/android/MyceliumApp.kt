package eu.mycellium.android

import android.app.Application

/**
 * Application entry point. The single [uniffi.mycellium_sdk.MyceliumClient] is
 * built lazily via [ClientHolder] the first time the ViewModel needs it (off the
 * main thread), so app startup stays cheap and the blocking store/Keystore work
 * never runs on the UI thread.
 */
class MyceliumApp : Application()
