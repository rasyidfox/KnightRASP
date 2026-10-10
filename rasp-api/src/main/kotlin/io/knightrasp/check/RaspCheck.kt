package io.knightrasp.check

import io.knightrasp.model.Category
import io.knightrasp.model.Evidence

/**
 * A single detection unit. Implementations must:
 *
 * - access the OS only through [RaspContext.probes] (so it can be unit-tested);
 * - not block longer than a reasonable timeout — the engine will cut the check off;
 * - return [CheckResult.Unknown] when a probe fails, instead of throwing an exception.
 */
interface RaspCheck {
    /** Stable id, used for configuration and allowlisting, e.g. `root.su_binary`. */
    val id: String

    val category: Category

    /** Determines execution order (LOW first) and the default timeout. */
    val cost: Cost

    fun run(ctx: RaspContext): CheckResult
}

enum class Cost { LOW, MEDIUM, HIGH }

sealed interface CheckResult {
    /** No indication. */
    data object Clean : CheckResult

    /** Detected; carries one or more evidence items. */
    data class Detected(val evidence: List<Evidence>) : CheckResult

    /** Inconclusive (probe failed / unsupported). Adds no score. */
    data class Unknown(val reason: String) : CheckResult
}
