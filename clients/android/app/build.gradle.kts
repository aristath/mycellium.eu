import java.io.File

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "eu.mycellium.android"
    compileSdk = 34

    defaultConfig {
        applicationId = "eu.mycellium.android"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"

        // Only bundle the ABIs cargo-ndk builds in build-rust.sh. Add/remove
        // here and in build-rust.sh together.
        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    // The cargo-ndk `.so` files land here (build-rust.sh writes to
    // src/main/jniLibs). They are a build artifact, so jniLibs/ is gitignored.
    sourceSets["main"].jniLibs.srcDirs("src/main/jniLibs")

    // The UniFFI-generated Kotlin binding (uniffi.mycellium_sdk.*) is generated
    // by build-rust.sh into build/generated/uniffi and wired in as a source set.
    // It is a build artifact — never committed, never hand-edited.
    sourceSets["main"].java.srcDir(layout.buildDirectory.dir("generated/uniffi"))
}

// Fail the build early with a clear message if the native `.so` / generated
// binding are missing, so the developer knows to run ./build-rust.sh first.
tasks.register("checkRustArtifacts") {
    doLast {
        val jniLibs = File(projectDir, "src/main/jniLibs")
        val binding = layout.buildDirectory
            .dir("generated/uniffi/uniffi/mycellium_sdk/mycellium_sdk.kt").get().asFile
        if (!jniLibs.exists() || jniLibs.listFiles().isNullOrEmpty()) {
            throw GradleException(
                "Native libraries missing under app/src/main/jniLibs. " +
                    "Run ./build-rust.sh from clients/android first (see README.md).",
            )
        }
        if (!binding.exists()) {
            throw GradleException(
                "Generated UniFFI Kotlin binding missing (${binding.path}). " +
                    "Run ./build-rust.sh from clients/android first (see README.md).",
            )
        }
    }
}

tasks.named("preBuild") {
    dependsOn("checkRustArtifacts")
}

dependencies {
    // AndroidX + lifecycle.
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.activity:activity-compose:1.9.2")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.6")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.6")

    // Jetpack Compose via the BOM (single source of truth for Compose versions).
    val composeBom = platform("androidx.compose:compose-bom:2024.09.02")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // Kotlin coroutines — every SDK call runs on Dispatchers.IO.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    // JNA — the UniFFI-generated Kotlin binding calls the Rust `.so` through JNA
    // at runtime. The `@aar` classifier pulls the Android artifact that bundles
    // JNA's own native libraries per ABI; a plain `:jna:` (jar) will crash at
    // runtime on device with UnsatisfiedLinkError. This is required.
    implementation("net.java.dev.jna:jna:5.14.0@aar")
}
