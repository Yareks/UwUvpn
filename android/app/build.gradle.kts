plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "app.velox.vpn"
    compileSdk = 35
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "app.velox.vpn"
        // Supports Android 7.0 (API 24) through Android 16, explicitly optimized for Android 12 (API 31/32)
        minSdk = 24
        targetSdk = 35
        versionCode = 107
        versionName = "1.7.0"

        ndk {
            // Covers 100% of 64-bit and 32-bit ARM Android smartphones while keeping APK compact
            abiFilters += listOf("arm64-v8a", "armeabi-v7a")
        }

        resourceConfigurations += listOf("ru", "en")
        vectorDrawables.useSupportLibrary = true
    }

    signingConfigs {
        create("release") {
            val ksPath = System.getenv("VELOX_KS_FILE")
            val ksPass = System.getenv("VELOX_KS_PASS")
            val ksFile = if (!ksPath.isNullOrBlank()) file(ksPath) else rootProject.file("keystore/velox-release.jks")
            if (ksFile.exists() && !ksPass.isNullOrBlank()) {
                storeFile = ksFile
                storePassword = ksPass
                keyAlias = System.getenv("VELOX_KEY_ALIAS") ?: "velox"
                keyPassword = System.getenv("VELOX_KEY_PASS") ?: ksPass
                enableV1Signing = true
                enableV2Signing = true
                enableV3Signing = true
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            val relSign = signingConfigs.getByName("release")
            signingConfig = if (relSign.storeFile != null) relSign else signingConfigs.getByName("debug")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        jniLibs {
            // Deflate-compress stripped 16 KiB-aligned Rust .so libraries -> compact APK!
            useLegacyPackaging = true
            // Prefer our app's jniLibs/libxray_ffi.so (xray-rust v0.10.0 + REALITY X.509 v1
            // sing-box/ShukaVPN/WL-RF SPKI CertificateVerify fix) over the upstream AAR copy!
            pickFirsts += "**/libxray_ffi.so"
        }
        resources {
            excludes += setOf(
                "/META-INF/{AL2.0,LGPL2.1}",
                "/META-INF/*.kotlin_module",
                "/META-INF/LICENSE*",
                "/META-INF/NOTICE*",
                "DebugProbesKt.bin"
            )
        }
    }
}

dependencies {
    // Official MPL-2.0 pure-Rust Xray engine (VLESS Reality/XHTTP/Vision, Hysteria2, MASQUE WARP, WG, Opera HTTPS)
    implementation("io.github.aimalygin:xray-rust-mobile:0.10.0")

    // Ultra-lean native Compose Material 3 UI — zero ads, zero analytics, zero Play Services
    val composeBom = platform("androidx.compose:compose-bom:2024.10.01")
    implementation(composeBom)
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.material3:material3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
}
