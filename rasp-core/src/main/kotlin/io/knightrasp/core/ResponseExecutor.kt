package io.knightrasp.core

import android.os.Process
import io.knightrasp.config.HostActions
import io.knightrasp.config.Mode
import io.knightrasp.config.Response
import io.knightrasp.model.RaspError
import io.knightrasp.model.ThreatAssessment
import io.knightrasp.telemetry.TelemetrySink

/**
 * Mengeksekusi [Response] hasil policy. Dipanggil di main thread.
 *
 * Pada [Mode.MONITOR], response yang dapat mengganggu pengguna (`Exit`, `Degrade`,
 * `Logout`, `BlockSensitiveOps`) dilewati dan hanya dicatat di log.
 *
 * @param killProcess aksi untuk [Response.Exit]; default memakai `android.os.Process`.
 *   Runtime produksi mengarahkannya ke `NativeProbe.killProcess` (syscall langsung)
 *   bila tersedia.
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
                            "Response gagal dieksekusi: $response",
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
                        RaspError(RaspError.Code.TELEMETRY_FAILURE, "TelemetrySink.report gagal.", it)
                    )
                }

            Response.Exit -> if (mode == Mode.PROTECT) {
                if (RaspLog.ENABLED) {
                    RaspLog.w("Exit dieksekusi (mode PROTECT).")
                }
                killProcess()
            } else {
                suppressed("Exit")
            }

            Response.Degrade -> if (mode == Mode.PROTECT) {
                if (RaspLog.ENABLED) {
                    RaspLog.w("Degrade dieksekusi (mode PROTECT).")
                }
                hostActions.degrade(assessment)
            } else {
                suppressed("Degrade")
            }

            Response.Logout -> if (mode == Mode.PROTECT) {
                if (RaspLog.ENABLED) {
                    RaspLog.w("Logout dieksekusi (mode PROTECT).")
                }
                hostActions.logout(assessment)
            } else {
                suppressed("Logout")
            }

            Response.BlockSensitiveOps -> if (mode == Mode.PROTECT) {
                if (RaspLog.ENABLED) {
                    RaspLog.w("BlockSensitiveOps dieksekusi (mode PROTECT).")
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
            RaspLog.w("$name diminta tetapi mode MONITOR; dilewati.")
        }
    }

    private companion object {
        const val MAX_LOGGED_EVIDENCE = 10
    }
}
