plugins {
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.kotlin.android) apply false
}

// Identitas publikasi seluruh modul SDK.
// Modul library masing-masing punya plugin `maven-publish` + `publishing { singleVariant }`,
// jalankan `./gradlew publishToMavenLocal` untuk konsumsi lokal.
subprojects {
    group = "io.knightrasp"
    version = "0.1.0"
}
