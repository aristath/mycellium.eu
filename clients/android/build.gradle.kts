// Root build file. Plugin versions are declared here with `apply false` and
// applied in the module build files. Keep these in sync with the Compose
// compiler plugin version (it must match the Kotlin version exactly).

plugins {
    id("com.android.application") version "8.5.2" apply false
    id("org.jetbrains.kotlin.android") version "2.0.20" apply false
    // The Compose compiler moved into the Kotlin distribution in Kotlin 2.0;
    // its Gradle plugin version MUST equal the Kotlin version above.
    id("org.jetbrains.kotlin.plugin.compose") version "2.0.20" apply false
}
