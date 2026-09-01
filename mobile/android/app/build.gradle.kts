// Copyright 2026 Blink Labs Software
// Licensed under the Apache License, Version 2.0.

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "io.blinklabs.bursa"
    compileSdk = 35
    buildToolsVersion = "35.0.0"

    defaultConfig {
        applicationId = "io.blinklabs.bursa"
        minSdk = 24
        targetSdk = 35
        // A tag build stamps the released version through the environment; a
        // local build keeps the placeholder so it stays buildable without one.
        versionCode = (System.getenv("BURSA_VERSION_CODE") ?: "1").toInt()
        versionName = System.getenv("BURSA_VERSION_NAME") ?: "0.1.0"
    }

    // Release signing is configured only when the keystore material is present.
    // Leaving the config absent (rather than defining one with empty values)
    // makes an unsigned release build fail loudly at the signing step instead of
    // producing an APK that looks releasable but cannot be installed.
    val keystorePath = System.getenv("BURSA_KEYSTORE_PATH")
    val hasKeystore = !keystorePath.isNullOrBlank() && file(keystorePath).exists()

    signingConfigs {
        if (hasKeystore) {
            create("release") {
                storeFile = file(keystorePath!!)
                storePassword = System.getenv("BURSA_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("BURSA_KEY_ALIAS")
                keyPassword = System.getenv("BURSA_KEY_PASSWORD")
                enableV1Signing = true
                enableV2Signing = true
            }
        }
    }

    buildTypes {
        getByName("debug") {
            isMinifyEnabled = false
        }
        getByName("release") {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            if (hasKeystore) {
                signingConfig = signingConfigs.getByName("release")
            }
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
    //   gomobile bind -target=android/arm64 -androidapi 24 -javapkg io.blinklabs.bursa \
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
