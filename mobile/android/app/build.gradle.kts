// Copyright 2026 Blink Labs Software
// Licensed under the Apache License, Version 2.0.

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.blinklabs.bursa"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.blinklabs.bursa"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
        }
        getByName("release") {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    // The gomobile AAR is dropped here by CI / the Docker build:
    //   gomobile bind -target=android -androidapi 24 -javapkg io.blinklabs.bursa \
    //       -o ../mobile/android/app/libs/bursa.aar ./mobile
    // It already bundles the per-ABI native .so libraries, so no extra ABI/NDK
    // config is needed in this module.
}

dependencies {
    // The gomobile-generated binding (the embedded wallet core). Consumed as a
    // local AAR so the app does not depend on a published artifact.
    implementation(files("libs/bursa.aar"))

    implementation("androidx.appcompat:appcompat:1.7.0")
    // NotificationCompat / ContextCompat for the foreground-service notification
    // and the startForegroundService + permission-check helpers.
    implementation("androidx.core:core-ktx:1.13.1")
    // registerForActivityResult / ActivityResultContracts for the runtime
    // POST_NOTIFICATIONS request on API 33+.
    implementation("androidx.activity:activity-ktx:1.9.3")
}
