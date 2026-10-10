package io.knightrasp.config

import io.knightrasp.model.ThreatAssessment
import io.knightrasp.telemetry.TelemetrySink

/**
 * SDK configuration.
 *
 * @param mode MONITOR: harmful responses (Exit, Degrade, Logout, BlockSensitiveOps) are
 *   not executed; PROTECT: they are fully executed.
 * @param environment QA disables blocking for development devices (a later version
 *   adds an emulator/team-device allowlist).
 * @param enabledChecks list of enabled `checkId`s; empty means all.
 * @param disabledChecks list of disabled `checkId`s; takes precedence over [enabledChecks].
 * @param thresholds score thresholds for mapping to [io.knightrasp.model.Level].
 * @param policy function that maps an assessment to a list of [Response]s.
 * @param telemetry telemetry sink; by default it sends nothing.
 * @param multiProcess MAIN_ONLY: only the main process runs the RASP engine.
 * @param expectedSignatureSha256 SHA-256 (hex, lowercase) of the accepted signing
 *   certificate. When empty, `integrity.signature` reports Unknown (no verification).
 * @param allowedInstallers installer packages considered acceptable (e.g.
 *   `com.android.vending`). When empty, `integrity.installer` reports Unknown.
 * @param hostActions app-level action implementation; by default it does nothing.
 * @param rules tuning from verified remote rules; null means no rules.
 * @param allowedAccessibilityServices accessibility service ids (`package/class`)
 *   considered acceptable (e.g. TalkBack). When empty, `env.accessibility_services` reports
 *   Unknown to avoid accusing too early.
 * @param debugLogging enables internal SDK logging. Default `false` (silent) — in
 *   release builds the logging code is absent entirely.
 */
data class RaspConfig @JvmOverloads constructor(
    val mode: Mode = Mode.MONITOR,
    val environment: Environment = Environment.RELEASE,
    val enabledChecks: Set<String> = emptySet(),
    val disabledChecks: Set<String> = emptySet(),
    val thresholds: Thresholds = Thresholds(),
    val policy: Policy = Policy.ALERT_ONLY,
    val telemetry: TelemetrySink = TelemetrySink.NOOP,
    val multiProcess: MultiProcessMode = MultiProcessMode.MAIN_ONLY,
    val expectedSignatureSha256: Set<String> = emptySet(),
    val allowedInstallers: Set<String> = emptySet(),
    val hostActions: HostActions = HostActions.NONE,
    val rules: RaspRules? = null,
    val allowedAccessibilityServices: Set<String> = emptySet(),
    val debugLogging: Boolean = false,
)

enum class Mode { MONITOR, PROTECT }

enum class Environment { RELEASE, QA }

enum class MultiProcessMode { MAIN_ONLY, ALL }

/**
 * Score thresholds (0..1). Standard mapping:
 * `score >= high` → CRITICAL, `>= medium` → HIGH, `>= low` → MEDIUM, `> 0` → LOW.
 */
data class Thresholds(
    val low: Float = 0.30f,
    val medium: Float = 0.60f,
    val high: Float = 0.85f,
)

/** App-owned policy: assessment → requested responses. */
fun interface Policy {
    fun responsesFor(assessment: ThreatAssessment): List<Response>

    companion object {
        /** Default: log and report, with no user-disrupting actions. */
        @JvmField
        val ALERT_ONLY: Policy = Policy { listOf(Response.Log, Response.Report) }
    }
}

/**
 * Actions requested by the [Policy].
 *
 * The `Exit`, `Degrade`, `Logout`, and `BlockSensitiveOps` responses are executed only in
 * [Mode.PROTECT]; in [Mode.MONITOR] they are all skipped (only logged).
 */
sealed interface Response {
    /** Writes an assessment summary to logcat. */
    data object Log : Response

    /** Sends the assessment to the configured [TelemetrySink]. */
    data object Report : Response

    /** Stops the app process (native syscall when available). */
    data object Exit : Response

    /** Asks the host to temporarily disable sensitive features via [HostActions.degrade]. */
    data object Degrade : Response

    /** Asks the host to clear the session and force a re-login via [HostActions.logout]. */
    data object Logout : Response

    /** Asks the host to block sensitive operations via [HostActions.blockSensitiveOps]. */
    data object BlockSensitiveOps : Response

    /** App-owned action; invoked on the main thread. */
    data class Custom(val action: () -> Unit) : Response
}
