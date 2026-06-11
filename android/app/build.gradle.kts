import org.gradle.kotlin.dsl.support.listFilesOrdered

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.maven.publish)
    alias(libs.plugins.rust.gradle)
}

object Library {
    const val groupId = "com.github.acurast"
    const val artifactId = "quic-tunnel"
    const val version = "0.1.4"
}

android {
    namespace = "com.acurast.tunnel"
    compileSdk = 35
    ndkVersion = sdkDirectory.resolve("ndk").listFilesOrdered().last().name

    defaultConfig {
        minSdk = 26
        version = Library.version

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
}

kotlin {
    explicitApiWarning()
}

cargo {
    module = "../../tunnel-client-ffi"
    libname = "tunnel_client_ffi"
    targets = listOf("arm", "arm64")
    profile = "release"
    prebuiltToolchains = true
    apiLevel = 29
    // Cargo workspace target/ lives at quic-tunnel/target, resolved relative to gradle project dir.
    targetDirectory = "../../target"
}

publishing {
    publications {
        register<MavenPublication>("maven") {
            groupId = Library.groupId
            artifactId = Library.artifactId
            version = Library.version

            afterEvaluate {
                from(components["release"])
            }
        }
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    compileOnly(libs.jna)
    implementation(libs.kotlinx.coroutines.core)
    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}

val ffiBuild: TaskProvider<Task> = tasks.register("ffiBuild", Task::class.java) {
    dependsOn("cargoBuild")

    doLast {
        exec {
            workingDir("../../tunnel-client-ffi")
            executable("cargo")
            args(
                "run", "--release",
                "--bin", "uniffi-bindgen",
                "generate",
                "--library", "../target/aarch64-linux-android/release/libtunnel_client_ffi.so",
                "--language", "kotlin",
                "--out-dir", "../android/app/src/main/java/com/acurast/tunnel"
            )
        }
    }
}

tasks.configureEach {
    if (name == "mergeDebugJniLibFolders" || name == "mergeReleaseJniLibFolders") {
        dependsOn("ffiBuild")
    }
}

tasks.matching { it.name.startsWith("compile") && it.name.endsWith("Kotlin") }.configureEach {
    dependsOn("ffiBuild")
}
