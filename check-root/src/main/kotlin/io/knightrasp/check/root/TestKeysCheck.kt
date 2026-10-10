package io.knightrasp.check.root

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.SystemProbe

/** Build dengan tag `test-keys` menandakan image tidak ditandatangani kunci rilis. */
class TestKeysCheck(private val system: SystemProbe) : RaspCheck {

    override val id = "root.test_keys"
    override val category = Category.ROOT
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val tags = system.tags
        return if (tags.contains("test-keys")) {
            CheckResult.Detected(listOf(Evidence(id, CONFIDENCE, "tags=$tags")))
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.4f
    }
}
