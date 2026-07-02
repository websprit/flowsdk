import groovy.json.JsonSlurper

pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.PREFER_SETTINGS)
    repositories {
        google()
        mavenCentral()
        maven {
            url = uri(findRustlsPlatformVerifierMavenRepo())
            metadataSources {
                artifact()
            }
        }
    }
}

rootProject.name = "flowsdk-kotlin"

include("package")
include("examples:simple_client")
include("examples:quic_client")
include("examples:android_quic_stability")

fun findRustlsPlatformVerifierMavenRepo(): File {
    val output = providers.exec {
        workingDir = File(rootDir, "..")
        commandLine(
            "cargo",
            "metadata",
            "--format-version",
            "1",
            "--features",
            "quic",
            "--filter-platform",
            "aarch64-linux-android",
            "--manifest-path",
            "flowsdk_ffi/Cargo.toml",
        )
    }.standardOutput.asText.get()

    val packages = JsonSlurper().parseText(output) as Map<*, *>
    val packageList = packages["packages"] as List<*>
    val verifierPackage = packageList
        .filterIsInstance<Map<*, *>>()
        .first { it["name"] == "rustls-platform-verifier-android" }
    val manifestPath = File(verifierPackage["manifest_path"] as String)
    return File(manifestPath.parentFile, "maven")
}
