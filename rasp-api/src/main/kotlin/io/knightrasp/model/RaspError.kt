package io.knightrasp.model

/** Error internal SDK. SDK bersifat fail-open: error tidak pernah menjatuhkan aplikasi. */
data class RaspError(
    val code: Code,
    val message: String,
    val cause: Throwable? = null,
) {
    enum class Code {
        NOT_INITIALIZED,
        INVALID_CONFIG,
        CHECK_FAILURE,
        SCAN_TIMEOUT,
        TELEMETRY_FAILURE,
        ENGINE_FAILURE,
    }
}
