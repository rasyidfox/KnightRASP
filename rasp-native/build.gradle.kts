import org.gradle.api.publish.maven.MavenPublication

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    `maven-publish`
}

// Native lib file name (without the word "rasp"), used by CMake and BuildConfig.
val nativeLibName: String = (findProperty("knightrasp.nativeLibName") as String?) ?: "guardcore"
val nativeLibKey: Int = 0x5A
val nativeLibNameObf: String = nativeLibName.toByteArray(Charsets.UTF_8)
    .joinToString(separator = "") { byte -> "%02x".format((byte.toInt() and 0xFF) xor nativeLibKey) }

android {
    namespace = "io.knightrasp.nativebridge"
    compileSdk = libs.versions.compileSdk.get().toInt()
    buildToolsVersion = libs.versions.buildTools.get()
    ndkVersion = libs.versions.ndk.get()

    defaultConfig {
        minSdk = libs.versions.minSdk.get().toInt()

        buildConfigField("String", "NATIVE_LIB_NAME_OBF", "\"$nativeLibNameObf\"")
        buildConfigField("int", "NATIVE_LIB_NAME_KEY", nativeLibKey.toString())

        ndk {
            // ABIs supported by the native library. x86_64 is included for emulator/testing.
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
            // The CMake version is determined by the SDK (`cmake;3.22.1`) or `cmake.dir`
            // in local.properties for custom installations.
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
