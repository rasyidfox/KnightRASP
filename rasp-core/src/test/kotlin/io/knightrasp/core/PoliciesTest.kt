package io.knightrasp.core

import io.knightrasp.config.Policies
import io.knightrasp.config.Response
import io.knightrasp.model.Level
import io.knightrasp.model.ThreatAssessment
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PoliciesTest {

    private fun assessment(level: Level) = ThreatAssessment(
        score = 0.9f,
        level = level,
        categories = emptyMap(),
        evidence = emptyList(),
        timestampMs = 1L,
    )

    @Test
    fun below_threshold_requests_nothing() {
        val policy = Policies.silentKillOn(Level.HIGH)

        assertTrue(policy.responsesFor(assessment(Level.MEDIUM)).isEmpty())
        assertTrue(policy.responsesFor(assessment(Level.NONE)).isEmpty())
    }

    @Test
    fun at_or_above_threshold_requests_exit() {
        val policy = Policies.silentKillOn(Level.HIGH)

        assertEquals(listOf(Response.Exit), policy.responsesFor(assessment(Level.HIGH)))
        assertEquals(listOf(Response.Exit), policy.responsesFor(assessment(Level.CRITICAL)))
    }

    @Test
    fun report_then_kill_orders_report_before_exit() {
        val policy = Policies.reportThenSilentKillOn(Level.HIGH)

        assertEquals(
            listOf(Response.Report, Response.Exit),
            policy.responsesFor(assessment(Level.CRITICAL)),
        )
    }
}
