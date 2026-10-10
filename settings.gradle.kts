pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "KnightRASP"

include(
    ":rasp-api",
    ":rasp-core",
    ":rasp-probes",
    ":rasp-native",
    ":rasp-testing",
    ":rasp-telemetry",
    ":rasp-rules",
    ":rasp-playintegrity",
    ":check-root",
    ":check-debug",
    ":check-emulator",
    ":check-environment",
    ":check-hook",
    ":check-integrity",
    ":check-virtualization",
    ":rasp",
    ":sample",
)
