package io.knightrasp.core

import io.knightrasp.check.RaspCheck
import io.knightrasp.config.RaspConfig
import io.knightrasp.config.RaspRules

/** Registry check dengan filter enable/disable dari [RaspConfig] dan remote rules. */
class CheckRegistry(private val all: List<RaspCheck>) {

    fun activeFor(config: RaspConfig, rules: RaspRules? = null): List<RaspCheck> {
        val enabled = config.enabledChecks
        val disabled = RuleTuner.disabledChecks(config, rules)
        return all.filter { check ->
            check.id !in disabled && (enabled.isEmpty() || check.id in enabled)
        }
    }

    fun allIds(): Set<String> = all.mapTo(LinkedHashSet()) { it.id }
}
