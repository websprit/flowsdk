plugins {
    id("com.android.application")
    kotlin("android")
}

group = "io.emqx.examples"
version = "0.1.0"

android {
    namespace = "io.emqx.flowsdk.examples.quicstability"
    compileSdk = 35

    defaultConfig {
        applicationId = "io.emqx.flowsdk.examples.quicstability"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    packaging {
        resources {
            excludes += "libflowsdk_ffi.dylib"
        }
    }
}

dependencies {
    implementation(project(":package")) {
        exclude(group = "net.java.dev.jna", module = "jna")
    }
    implementation(kotlin("stdlib"))
    implementation("net.java.dev.jna:jna:5.14.0@aar")
    implementation("rustls:rustls-platform-verifier:0.1.1@aar")
}
