package io.knightrasp.core

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.config.Thresholds
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.model.Level
import io.knightrasp.testing.testContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanEngineTest {

    private class CountingCheck(
        override val id: String,
        override val category: Category = Category.ROOT,
        override val cost: Cost = Cost.LOW,
        private val result: CheckResult = CheckResult.Clean,
        private val action: (() -> Unit)? = null,
    ) : RaspCheck {
        var runs = 0
            private set

        override fun run(ctx: RaspContext): CheckResult {
            runs++
            action?.invoke()
            return result
        }
    }

    private fun engineWith(vararg checks: RaspCheck) = ScanEngine(
        checks = checks.toList(),
        scorer = Scorer(Thresholds()),
        cache = TtlCache(),
        workScope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
    )

    @Test
    fun clean_checks_produce_none() = runBlocking {
        val result = engineWith(CountingCheck("clean")).scan(testContext())
        assertEquals(Level.NONE, result.level)
        assertEquals(0, result.evidence.size)
    }

    @Test
    fun detected_check_adds_evidence_and_score() = runBlocking {
        val check = CountingCheck(
            "root.su_binary",
            category = Category.ROOT,
            result = CheckResult.Detected(listOf(Evidence("root.su_binary", 0.7f))),
        )
        val result = engineWith(check).scan(testContext())
        assertEquals(Level.HIGH, result.level)
        assertEquals(1, result.evidence.size)
    }

    @Test
    fun failing_check_is_isolated() = runBlocking {
        val failing = CountingCheck("boom", action = { error("boom") })
        val detected = CountingCheck(
            "ok",
            result = CheckResult.Detected(listOf(Evidence("ok", 0.7f))),
        )
        val failures = mutableListOf<String>()

        val result = engineWith(failing, detected).scan(testContext()) { id, _ -> failures += id }

        assertEquals(listOf("boom"), failures)
        assertEquals(1, result.evidence.size)
    }

    @Test
    fun low_cost_wave_runs_before_other_waves() = runBlocking {
        val order = mutableListOf<String>()
        val low = CountingCheck("low", cost = Cost.LOW, action = { order += "low" })
        val high = CountingCheck("high", cost = Cost.HIGH, action = { order += "high" })

        engineWith(high, low).scan(testContext())

        assertEquals(listOf("low", "high"), order)
    }

    @Test
    fun results_are_cached_between_scans() = runBlocking {
        val check = CountingCheck(
            "cached",
            result = CheckResult.Detected(listOf(Evidence("cached", 0.5f))),
        )
        val engine = engineWith(check)

        engine.scan(testContext())
        engine.scan(testContext())
        assertEquals(1, check.runs)

        engine.scan(testContext(), useCache = false)
        assertEquals(2, check.runs)
    }

    @Test
    fun unknown_results_are_not_cached() = runBlocking {
        val check = CountingCheck("unknown", result = CheckResult.Unknown("probe gagal"))
        val engine = engineWith(check)

        engine.scan(testContext())
        engine.scan(testContext())
        assertEquals(2, check.runs)
    }

    @Test
    fun evidence_tuner_is_applied_to_outcomes() = runBlocking {
        val engine = ScanEngine(
            checks = listOf(
                CountingCheck(
                    "scaled",
                    result = CheckResult.Detected(listOf(Evidence("scaled", 0.8f))),
                )
            ),
            scorer = Scorer(Thresholds()),
            cache = TtlCache(),
            workScope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
            evidenceTuner = { _, evidence -> evidence.map { it.copy(confidence = 0.1f) } },
        )

        val result = engine.scan(testContext())

        assertEquals(0.1f, result.evidence.single().confidence, 0.0001f)
        assertEquals(Level.LOW, result.level)
    }

    @Test
    fun slow_check_is_abandoned_after_timeout() = runBlocking {
        val slow = CountingCheck(
            "slow",
            cost = Cost.LOW,
            result = CheckResult.Detected(listOf(Evidence("slow", 0.9f))),
            action = { Thread.sleep(1_500L) },
        )
        val failures = mutableListOf<String>()

        val startedAt = System.currentTimeMillis()
        val result = engineWith(slow).scan(testContext()) { id, _ -> failures += id }
        val elapsed = System.currentTimeMillis() - startedAt

        assertEquals(listOf("slow"), failures)
        assertEquals(0, result.evidence.size)
        assertTrue("scan tidak boleh menunggu straggler, elapsed=${elapsed}ms", elapsed < 1_200L)
    }
}
