package io.knightrasp.check.emulator

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.SystemProbe

/**
 * Sinyal emulator dari build properties. Tidak ada satu sinyal pun yang menentukan;
 * setiap sinyal menambah confidence dan agregasi dilakukan scorer.
 */
class EmulatorPropsCheck(private val system: SystemProbe) : RaspCheck {

    override val id = "emulator.props"
    override val category = Category.EMULATOR
    override val cost = Cost.LOW

    override fun run(ctx: RaspContext): CheckResult {
        val evidence = mutableListOf<Evidence>()

        val fingerprint = system.fingerprint.lowercase()
        if (FINGERPRINT_MARKERS.any { it in fingerprint }) {
            evidence += Evidence(id, 0.5f, "fingerprint=${system.fingerprint}")
        }

        val model = system.model.lowercase()
        if (MODEL_MARKERS.any { it in model }) {
            evidence += Evidence(id, 0.4f, "model=${system.model}")
        }

        if (system.hardware.lowercase() in SUSPICIOUS_HARDWARE) {
            evidence += Evidence(id, 0.5f, "hardware=${system.hardware}")
        }

        if (system.product.lowercase() in SUSPICIOUS_PRODUCTS) {
            evidence += Evidence(id, 0.4f, "product=${system.product}")
        }

        val manufacturer = system.manufacturer.lowercase()
        if ("genymotion" in manufacturer) {
            evidence += Evidence(id, 0.6f, "manufacturer=${system.manufacturer}")
        }

        if (system.supportedAbis.any { it.startsWith("x86") }) {
            evidence += Evidence(id, 0.2f, "abis=${system.supportedAbis}")
        }

        return if (evidence.isEmpty()) CheckResult.Clean else CheckResult.Detected(evidence)
    }

    companion object {
        val FINGERPRINT_MARKERS = listOf("generic", "unknown", "emulator", "sdk_gphone", "vbox", "eden")
        val MODEL_MARKERS = listOf("google_sdk", "emulator", "android sdk built for", "sdk_gphone", "vbox")
        val SUSPICIOUS_HARDWARE = setOf("goldfish", "ranchu", "vbox86")
        val SUSPICIOUS_PRODUCTS = setOf("sdk", "google_sdk", "sdk_x86", "sdk_gphone", "vbox86p", "emulator")
    }
}
