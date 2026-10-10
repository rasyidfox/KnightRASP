plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
}

// Publication identity for all SDK modules.
// Each library module has the `maven-publish` plugin + `publishing { singleVariant }`;
// run `./gradlew publishToMavenLocal` for local consumption.
subprojects {
    group = "io.knightrasp"
    version = "0.1.0"
}
