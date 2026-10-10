package io.knightrasp.check.emulator

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.SystemProbe
import io.knightrasp.util.ObfuscatedStrings

/**
 * Emulator signals from build properties. No single signal is conclusive;
 * each signal adds confidence and the scorer aggregates them.
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
        if (GENYMOTION_MARKER in manufacturer) {
            evidence += Evidence(id, 0.6f, "manufacturer=${system.manufacturer}")
        }

        if (system.supportedAbis.any { it.startsWith("x86") }) {
            evidence += Evidence(id, 0.2f, "abis=${system.supportedAbis}")
        }

        return if (evidence.isEmpty()) CheckResult.Clean else CheckResult.Detected(evidence)
    }

    companion object {
        /** Obfuscated emulator markers (fingerprint/model/hardware/product). */
        val FINGERPRINT_MARKERS: List<String> = ObfuscatedStrings.decodeList(
            "76747f746378721b647f7a7f7e667f1b747c647d70657e631b62757a4e7661797e7f741b67737e691b7475747f",
            0x11,
        )

        val MODEL_MARKERS: List<String> = ObfuscatedStrings.decodeList(
            "4a42424a4148725e494627484058414c59425f274c43495f4244490d5e49460d4f584441590d4b425f275e" +
                "4946724a5d45424348275b4f4255",
            0x2D,
        )

        val SUSPICIOUS_HARDWARE: List<String> = ObfuscatedStrings.decodeList(
            "2e26252d2f203a21433b28272a213c433f2b2631717f",
            0x49,
        )

        val SUSPICIOUS_PRODUCTS: List<String> = ObfuscatedStrings.decodeList(
            "04131c7d101818101b122804131c7d04131c280f4f417d04131c2810071f1819127d0115180f4f41077d12" +
                "1a021b16031805",
            0x77,
        )

        private val GENYMOTION_MARKER: String = ObfuscatedStrings.decode("34363d2a3e3c273a3c3d", 0x53)
    }
}
