package io.knightrasp.core

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Evidence
import io.knightrasp.model.ThreatAssessment
import java.util.concurrent.TimeoutException
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Menjalankan check dalam dua gelombang (LOW dulu, lalu MEDIUM/HIGH), paralel di dalam
 * gelombang, dengan timeout dan isolasi per check.
 *
 * Check dieksekusi di [workScope] yang **tidak** di-join oleh scan, sehingga check yang
 * melewati timeout ditinggalkan (hasilnya dibuang) tanpa menahan scan. Coroutine
 * straggler akan selesai sendiri di thread I/O-nya.
 *
 * Hasil `Clean`/`Detected` di-cache sesuai TTL cost; `Unknown` dan kegagalan tidak
 * di-cache.
 */
class ScanEngine(
    checks: List<RaspCheck>,
    private val scorer: Scorer,
    private val cache: TtlCache,
    private val workScope: CoroutineScope,
    private val evidenceTuner: (checkId: String, evidence: List<Evidence>) -> List<Evidence> =
        { _, evidence -> evidence },
) {
    private val firstWave = checks.filter { it.cost == Cost.LOW }
    private val secondWave = checks.filter { it.cost != Cost.LOW }

    suspend fun scan(
        ctx: RaspContext,
        useCache: Boolean = true,
        onCheckFailure: (checkId: String, cause: Throwable) -> Unit = { _, _ -> },
    ): ThreatAssessment {
        val outcomes = mutableListOf<CheckOutcome>()
        for (wave in listOf(firstWave, secondWave)) {
            val waveOutcomes = coroutineScope {
                wave.map { check ->
                    async { runCheck(check, ctx, useCache, onCheckFailure) }
                }.awaitAll().filterNotNull()
            }
            outcomes += waveOutcomes
        }
        return scorer.assess(outcomes, ctx.nowMs)
    }

    private suspend fun runCheck(
        check: RaspCheck,
        ctx: RaspContext,
        useCache: Boolean,
        onCheckFailure: (checkId: String, cause: Throwable) -> Unit,
    ): CheckOutcome? {
        val ttl = ttlFor(check.cost)
        if (useCache) {
            when (val cached = cache.get(check.id, ttl)) {
                is CheckResult.Detected -> return CheckOutcome(
                    check.id,
                    check.category,
                    evidenceTuner(check.id, cached.evidence),
                )

                CheckResult.Clean -> return null
                else -> Unit
            }
        }

        val worker = workScope.async<WorkerResult> {
            try {
                WorkerResult.Value(check.run(ctx))
            } catch (t: Throwable) {
                if (t is CancellationException) throw t
                WorkerResult.Failure(t)
            }
        }

        val timeoutMs = timeoutFor(check.cost)
        val completed = withTimeoutOrNull(timeoutMs) { worker.await() }
        if (completed == null) {
            worker.cancel()
            onCheckFailure(check.id, TimeoutException("Check ${check.id} melewati ${timeoutMs}ms."))
            return null
        }

        val result = when (completed) {
            is WorkerResult.Failure -> {
                onCheckFailure(check.id, completed.cause)
                return null
            }
            is WorkerResult.Value -> completed.result
        }

        if (useCache && result !is CheckResult.Unknown) {
            cache.put(check.id, result, ttl)
        }
        return when (result) {
            is CheckResult.Detected -> CheckOutcome(
                check.id,
                check.category,
                evidenceTuner(check.id, result.evidence),
            )

            else -> null
        }
    }

    private sealed interface WorkerResult {
        data class Value(val result: CheckResult) : WorkerResult
        data class Failure(val cause: Throwable) : WorkerResult
    }

    companion object {
        fun timeoutFor(cost: Cost): Long = when (cost) {
            Cost.LOW -> 1_000L
            Cost.MEDIUM -> 2_000L
            Cost.HIGH -> 3_000L
        }

        fun ttlFor(cost: Cost): Long = when (cost) {
            Cost.LOW -> 30_000L
            Cost.MEDIUM -> 5 * 60_000L
            Cost.HIGH -> 30 * 60_000L
        }
    }
}
