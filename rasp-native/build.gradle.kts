import org.gradle.api.publish.maven.MavenPublication

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    `maven-publish`
}

// Nama file lib native (tanpa kata "rasp"), dipakai oleh CMake dan BuildConfig.
val nativeLibName: String = (findProperty("knightrasp.nativeLibName") as String?) ?: "guardcore"

android {
    namespace = "io.knightrasp.nativebridge"
    compileSdk = libs.versions.compileSdk.get().toInt()
    buildToolsVersion = libs.versions.buildTools.get()
    ndkVersion = libs.versions.ndk.get()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()

        buildConfigField("String", "NATIVE_LIB_NAME", "\"$nativeLibName\"")

        ndk {
            // ABI yang didukung library native. x86_64 disertakan untuk emulator/testing.
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }

        externalNativeBuild {
            cmake {
                arguments += "-DANDROID_STL=c++_static"
                arguments += "-DNATIVE_LIB_NAME=$nativeLibName"
                cppFlags += "-std=c++17"
            }
        }
    }

    buildFeatures {
        buildConfig = true
    }

    externalNativeBuild {
        cmake {
            // Versi CMake ditentukan oleh SDK (`cmake;3.22.1`) atau `cmake.dir`
            // di local.properties untuk instalasi kustom.
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    api(project(":rasp-api"))
}

android {
    publishing {
        singleVariant("release")
    }
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                from(components["release"])
                artifactId = project.name
            }
        }
    }
}
