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

    // Release signing is configured only when the keystore material is present,
    // so a debug build and an IDE sync still work without it. Absent signing
    // material does not make AGP fail, though: it would emit
    // app-release-unsigned.apk. The task-graph check below turns that into a
    // hard failure, so a release build can never quietly produce an APK that
    // looks releasable but cannot be installed.
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

// Refuse to run a release task without signing material rather than letting
// AGP emit an unsigned APK. Checked on the resolved task graph so it fires for
// assembleRelease/bundleRelease only, leaving debug builds and IDE sync alone.
gradle.taskGraph.whenReady {
    val keystorePath = System.getenv("BURSA_KEYSTORE_PATH")
    val hasKeystore = !keystorePath.isNullOrBlank() && File(keystorePath).exists()
    val releaseRequested = allTasks.any {
        it.project == project && it.name.endsWith("Release")
    }
    if (releaseRequested && !hasKeystore) {
        throw GradleException(
            "A release build requires signing material: set BURSA_KEYSTORE_PATH " +
                "(plus BURSA_KEYSTORE_PASSWORD, BURSA_KEY_ALIAS, BURSA_KEY_PASSWORD) " +
                "to an existing keystore. Refusing to produce an unsigned release APK.",
        )
    }
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
