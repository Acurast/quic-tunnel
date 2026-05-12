import groovy.json.JsonSlurper

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
        // rustls-platform-verifier ships its required Android Kotlin sidecar
        // (`rustls:rustls-platform-verifier:0.1.1`) inside the
        // `rustls-platform-verifier-android` crate as a flat maven repo.
        // Locate it via `cargo metadata` and register the repo here.
        val rpvDir = rustlsPlatformVerifierMaven()
        rpvDir?.let { dir ->
            maven {
                url = dir.toURI()
            }
        }
    }
}

rootProject.name = "tunnel-client"
include(":app")

fun rustlsPlatformVerifierMaven(): java.io.File? = try {
    val proc = ProcessBuilder(
        "cargo", "metadata",
        "--format-version", "1",
        "--filter-platform", "aarch64-linux-android",
        "--manifest-path", "../tunnel-client-ffi/Cargo.toml",
    ).directory(rootDir).redirectErrorStream(false).start()
    val out = proc.inputStream.bufferedReader().readText()
    val err = proc.errorStream.bufferedReader().readText()
    val rc = proc.waitFor()
    if (rc != 0) {
        println("cargo metadata failed rc=$rc stderr=$err")
        null
    } else {
        @Suppress("UNCHECKED_CAST")
        val parsed = JsonSlurper().parseText(out) as Map<String, Any?>
        val packages = parsed["packages"] as List<Map<String, Any?>>
        val pkg = packages.firstOrNull { it["name"] == "rustls-platform-verifier-android" }
        if (pkg == null) {
            println("rustls-platform-verifier-android not in cargo metadata")
            null
        } else {
            val manifestPath = pkg["manifest_path"] as String
            java.io.File(manifestPath).parentFile.resolve("maven")
        }
    }
} catch (e: Throwable) {
    println("rustlsPlatformVerifierMaven failed: $e")
    null
}
