package io.knightrasp.core

import android.os.Process
import io.knightrasp.config.HostActions
import io.knightrasp.config.Mode
import io.knightrasp.config.Response
import io.knightrasp.model.RaspError
import io.knightrasp.model.ThreatAssessment
import io.knightrasp.telemetry.TelemetrySink

/**
 * Executes the [Response]s produced by the policy. Called on the main thread.
 *
 * In [Mode.MONITOR], user-disrupting responses (`Exit`, `Degrade`,
 * `Logout`, `BlockSensitiveOps`) are skipped and only logged.
 *
 * @param killProcess action for [Response.Exit]; defaults to `android.os.Process`.
 *   The production runtime routes it to `NativeProbe.shutdown` (raw syscall)
 *   when available.
 */
class ResponseExecutor(
    private val mode: Mode,
    private val telemetry: TelemetrySink,
    private val hostActions: HostActions,
    private val killProcess: () -> Unit = { Process.killProcess(Process.myPid()) },
) {

    fun execute(
        responses: List<Response>,
        assessment: ThreatAssessment,
        onError: (RaspError) -> Unit,
    ) {
        for (response in responses) {
            runCatching { executeOne(response, assessment, onError) }
                .onFailure {
                    onError(
                        RaspError(
                            RaspError.Code.ENGINE_FAILURE,
                            "Response failed to execute: $response",
                            it,
                        )
                    )
                }
        }
    }

    private fun executeOne(
        response: Response,
        assessment: ThreatAssessment,
        onError: (RaspError) -> Unit,
    ) {
        when (response) {
            Response.Log -> if (RaspLog.ENABLED) {
                val categories = assessment.categories.entries
                    .sortedByDescending { it.value }
                    .joinToString { "${it.key}=${it.value}" }
                RaspLog.d(
                    "assessment level=${assessment.level} score=${assessment.score} " +
                        "categories=[$categories] evidence=${assessment.evidence.size}"
                )
                assessment.evidence.take(MAX_LOGGED_EVIDENCE).forEach { item ->
                    RaspLog.d(
                        "  evidence ${item.ruleId} confidence=${item.confidence} " +
                            "detail=${item.detail ?: "-"}"
                    )
                }
            }

            Response.Report -> runCatching { telemetry.report(assessment) }
                .onFailure {
                    onError(
                        RaspError(RaspError.Code.TELEMETRY_FAILURE, "TelemetrySink.report failed.", it)
                    )
                }

            Response.Exit -> if (mode == Mode.PROTECT) {
                if (RaspLog.ENABLED) {
                    RaspLog.w("Exit executed (PROTECT mode).")
                }
                killProcess()
            } else {
                suppressed("Exit")
            }

            Response.Degrade -> if (mode == Mode.PROTECT) {
                if (RaspLog.ENABLED) {
                    RaspLog.w("Degrade executed (PROTECT mode).")
                }
                hostActions.degrade(assessment)
            } else {
                suppressed("Degrade")
            }

            Response.Logout -> if (mode == Mode.PROTECT) {
                if (RaspLog.ENABLED) {
                    RaspLog.w("Logout executed (PROTECT mode).")
                }
                hostActions.logout(assessment)
            } else {
                suppressed("Logout")
            }

            Response.BlockSensitiveOps -> if (mode == Mode.PROTECT) {
                if (RaspLog.ENABLED) {
                    RaspLog.w("BlockSensitiveOps executed (PROTECT mode).")
                }
                hostActions.blockSensitiveOps(assessment)
            } else {
                suppressed("BlockSensitiveOps")
            }

            is Response.Custom -> response.action()
        }
    }

    private fun suppressed(name: String) {
        if (RaspLog.ENABLED) {
            RaspLog.w("$name requested but MONITOR mode; skipped.")
        }
    }

    private companion object {
        const val MAX_LOGGED_EVIDENCE = 10
    }
}
