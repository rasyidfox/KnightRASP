package io.knightrasp.core

import io.knightrasp.config.HostActions
import io.knightrasp.config.Mode
import io.knightrasp.config.Response
import io.knightrasp.model.Level
import io.knightrasp.model.RaspError
import io.knightrasp.model.ThreatAssessment
import io.knightrasp.telemetry.TelemetrySink
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class ResponseExecutorTest {

    private val assessment = ThreatAssessment(
        score = 0.9f,
        level = Level.CRITICAL,
        categories = emptyMap(),
        evidence = emptyList(),
        timestampMs = 1L,
    )

    private class FakeHost : HostActions {
        var degraded = false
        var loggedOut = false
        var blocked = false

        override fun degrade(assessment: ThreatAssessment) {
            degraded = true
        }

        override fun logout(assessment: ThreatAssessment) {
            loggedOut = true
        }

        override fun blockSensitiveOps(assessment: ThreatAssessment) {
            blocked = true
        }
    }

    private class FakeTelemetry : TelemetrySink {
        var last: ThreatAssessment? = null

        override fun report(assessment: ThreatAssessment) {
            last = assessment
        }
    }

    @Test
    fun monitor_suppresses_host_actions() {
        val host = FakeHost()
        val executor = ResponseExecutor(Mode.MONITOR, TelemetrySink.NOOP, host)

        executor.execute(
            listOf(Response.Degrade, Response.Logout, Response.BlockSensitiveOps),
            assessment,
        ) { }

        assertFalse(host.degraded)
        assertFalse(host.loggedOut)
        assertFalse(host.blocked)
    }

    @Test
    fun protect_invokes_host_actions() {
        val host = FakeHost()
        val executor = ResponseExecutor(Mode.PROTECT, TelemetrySink.NOOP, host)

        executor.execute(
            listOf(Response.Degrade, Response.Logout, Response.BlockSensitiveOps),
            assessment,
        ) { }

        assertTrue(host.degraded)
        assertTrue(host.loggedOut)
        assertTrue(host.blocked)
    }

    @Test
    fun monitor_suppresses_exit() {
        var killed = false
        val executor = ResponseExecutor(Mode.MONITOR, TelemetrySink.NOOP, HostActions.NONE) {
            killed = true
        }

        executor.execute(listOf(Response.Exit), assessment) { }

        assertFalse(killed)
    }

    @Test
    fun protect_exit_uses_injected_kill_process() {
        var killed = false
        val executor = ResponseExecutor(Mode.PROTECT, TelemetrySink.NOOP, HostActions.NONE) {
            killed = true
        }

        executor.execute(listOf(Response.Exit), assessment) { }

        assertTrue(killed)
    }

    @Test
    fun report_sends_assessment_to_telemetry() {
        val telemetry = FakeTelemetry()
        val executor = ResponseExecutor(Mode.MONITOR, telemetry, HostActions.NONE)

        executor.execute(listOf(Response.Report), assessment) { }

        assertSame(assessment, telemetry.last)
    }

    @Test
    fun telemetry_failure_is_reported_but_does_not_throw() {
        val telemetry = TelemetrySink { error("backend mati") }
        val executor = ResponseExecutor(Mode.MONITOR, telemetry, HostActions.NONE)
        val errors = mutableListOf<RaspError>()

        executor.execute(listOf(Response.Report), assessment) { errors += it }

        assertEquals(1, errors.size)
        assertEquals(RaspError.Code.TELEMETRY_FAILURE, errors.single().code)
    }

    @Test
    fun custom_action_runs_in_both_modes() {
        var ran = 0
        val executor = ResponseExecutor(Mode.MONITOR, TelemetrySink.NOOP, HostActions.NONE)

        executor.execute(listOf(Response.Custom { ran++ }), assessment) { }

        assertEquals(1, ran)
    }

    @Test
    fun throwing_custom_action_is_isolated() {
        val executor = ResponseExecutor(Mode.PROTECT, TelemetrySink.NOOP, HostActions.NONE)
        val errors = mutableListOf<RaspError>()
        var secondRan = false

        executor.execute(
            listOf(
                Response.Custom { error("aksi rusak") },
                Response.Custom { secondRan = true },
            ),
            assessment,
        ) { errors += it }

        assertTrue(secondRan)
        assertEquals(RaspError.Code.ENGINE_FAILURE, errors.single().code)
    }
}
