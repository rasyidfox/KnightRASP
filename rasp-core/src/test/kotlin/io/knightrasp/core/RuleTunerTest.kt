package io.knightrasp.core

import io.knightrasp.config.Environment
import io.knightrasp.config.RaspConfig
import io.knightrasp.config.RaspRules
import io.knightrasp.config.Thresholds
import io.knightrasp.model.Evidence
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

class RuleTunerTest {

    @Test
    fun expired_rules_are_ignored() {
        val config = RaspConfig(rules = RaspRules(version = 1, expiresAtMs = 100L))

        assertNull(RuleTuner.activeRules(config, nowMs = 101L))
        assertTrue(RuleTuner.activeRules(config, nowMs = 100L) != null)
    }

    @Test
    fun thresholds_override_when_rules_present() {
        val custom = Thresholds(low = 0.1f, medium = 0.2f, high = 0.3f)
        val config = RaspConfig(thresholds = Thresholds())

        val effective = RuleTuner.effectiveThresholds(
            config,
            RaspRules(version = 1, thresholds = custom),
        )

        assertSame(custom, effective)
    }

    @Test
    fun thresholds_fall_back_without_rules() {
        val config = RaspConfig()
        assertSame(config.thresholds, RuleTuner.effectiveThresholds(config, null))
    }

    @Test
    fun disabled_checks_are_merged() {
        val config = RaspConfig(disabledChecks = setOf("a"))
        val rules = RaspRules(version = 1, disabledChecks = setOf("b"))

        val disabled = RuleTuner.disabledChecks(config, rules)

        assertTrue(disabled.containsAll(setOf("a", "b")))
    }

    @Test
    fun qa_environment_disables_development_noise_checks() {
        val config = RaspConfig(environment = Environment.QA)

        val disabled = RuleTuner.disabledChecks(config, rules = null)

        assertEquals(RuleTuner.QA_DISABLED_CHECKS, disabled)
    }

    @Test
    fun release_environment_keeps_development_checks_enabled() {
        val config = RaspConfig(environment = Environment.RELEASE)

        assertEquals(emptySet<String>(), RuleTuner.disabledChecks(config, rules = null))
    }

    @Test
    fun confidence_is_scaled_and_clamped() {
        val tuner = RuleTuner.evidenceTuner(
            RaspRules(
                version = 1,
                confidenceScale = mapOf("root.su_binary" to 0.5f, "boosted" to 3f),
            )
        )

        val scaled = tuner("root.su_binary", listOf(Evidence("root.su_binary", 0.8f)))
        assertEquals(0.4f, scaled.single().confidence, 0.0001f)

        val clamped = tuner("boosted", listOf(Evidence("boosted", 0.8f)))
        assertEquals(1f, clamped.single().confidence, 0.0001f)

        val untouched = tuner("unknown", listOf(Evidence("unknown", 0.8f)))
        assertEquals(0.8f, untouched.single().confidence, 0.0001f)
    }

    @Test
    fun zero_scale_effectively_disables_evidence() {
        val tuner = RuleTuner.evidenceTuner(
            RaspRules(version = 1, confidenceScale = mapOf("noisy" to 0f))
        )

        val muted = tuner("noisy", listOf(Evidence("noisy", 0.9f)))

        assertEquals(0f, muted.single().confidence, 0.0001f)
    }
}
