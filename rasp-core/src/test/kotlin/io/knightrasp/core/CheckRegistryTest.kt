package io.knightrasp.core

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.config.RaspConfig
import io.knightrasp.config.RaspRules
import io.knightrasp.model.Category
import org.junit.Assert.assertEquals
import org.junit.Test

class CheckRegistryTest {

    private class FakeCheck(override val id: String) : RaspCheck {
        override val category = Category.ROOT
        override val cost = Cost.LOW

        override fun run(ctx: RaspContext): CheckResult = CheckResult.Clean
    }

    @Test
    fun disabled_from_config_and_rules_are_merged() {
        val registry = CheckRegistry(listOf(FakeCheck("a"), FakeCheck("b"), FakeCheck("c")))
        val config = RaspConfig(disabledChecks = setOf("a"))
        val rules = RaspRules(version = 1, disabledChecks = setOf("b"))

        assertEquals(listOf("c"), registry.activeFor(config, rules).map { it.id })
    }

    @Test
    fun enabled_list_acts_as_allowlist() {
        val registry = CheckRegistry(listOf(FakeCheck("a"), FakeCheck("b")))
        val config = RaspConfig(enabledChecks = setOf("b"))

        assertEquals(listOf("b"), registry.activeFor(config).map { it.id })
    }

    @Test
    fun all_checks_active_by_default() {
        val registry = CheckRegistry(listOf(FakeCheck("a"), FakeCheck("b")))

        assertEquals(listOf("a", "b"), registry.activeFor(RaspConfig()).map { it.id })
    }
}
