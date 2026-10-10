package io.knightrasp.testing

import io.knightrasp.check.RaspContext
import io.knightrasp.config.RaspConfig
import io.knightrasp.probe.Probes

/** Membuat [RaspContext] untuk unit test dengan nilai default yang bisa dioverride. */
fun testContext(
    probes: Probes = TestProbes(),
    config: RaspConfig = RaspConfig(),
    packageName: String = "io.knightrasp.test",
    nowMs: Long = 42L,
): RaspContext = object : RaspContext {
    override val config = config
    override val probes = probes
    override val packageName = packageName
    override val nowMs = nowMs
}
