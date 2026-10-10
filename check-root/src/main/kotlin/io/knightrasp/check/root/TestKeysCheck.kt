package io.knightrasp.check.root

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.SystemProbe
import io.knightrasp.util.ObfuscatedStrings

/** A build tagged `test-keys` means the image is not signed with release keys. */
class TestKeysCheck(private val system: SystemProbe) : RaspCheck {

    override val id = "root.test_keys"
    override val category = Category.ROOT
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val tags = system.tags
        return if (tags.contains(TEST_KEYS_MARKER)) {
            CheckResult.Detected(listOf(Evidence(id, CONFIDENCE, "tags=$tags")))
        } else {
            CheckResult.Clean
        }
    }

    companion object {
        const val CONFIDENCE = 0.4f

        /** Obfuscated "test-keys". */
        private val TEST_KEYS_MARKER: String = ObfuscatedStrings.decode("5d4c5a5d04424c505a", 0x29)
    }
}
