package io.knightrasp.model

/** SDK internal error. The SDK is fail-open: errors never crash the app. */
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
