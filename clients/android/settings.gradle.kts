// Mycellium Android client — Gradle settings.
//
// This project is intentionally OUTSIDE the Cargo workspace and outside the
// repo's normal CI: there is no Android toolchain in main CI. See README.md.

pluginManagement {
    repositories {
        google {
            content {
                includeGroupByRegex("com\\.android.*")
                includeGroupByRegex("com\\.google.*")
                includeGroupByRegex("androidx.*")
            }
        }
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "mycellium-android"
include(":app")
