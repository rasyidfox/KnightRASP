package io.knightrasp.check.hook

import io.knightrasp.check.CheckResult
import io.knightrasp.check.Cost
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.probe.ProcProbe
import io.knightrasp.util.TextCodec

/**
 * Hooking-framework artifacts (Frida/Xposed/Substrate) visible in the process memory
 * map. This is the strongest signal in the hook category; use it together with
 * `hook.frida_threads` and the native check.
 */
class FridaMapsCheck(private val proc: ProcProbe) : RaspCheck {

    override val id = "hook.maps_artifacts"
    override val category = Category.HOOK
    override val cost = Cost.MEDIUM

    override fun run(ctx: RaspContext): CheckResult {
        val maps = proc.selfMaps()
            ?: return CheckResult.Unknown("maps unreadable")

        // Lowercase once, then use the fast native indexOf. The
        // contains(ignoreCase = true) path proved too slow on cold start (it compares
        // per character at every position in a multi-megabyte string).
        val haystack = maps.lowercase()
        val matches = MARKERS.filter { marker -> marker in haystack }
        return if (matches.isEmpty()) {
            CheckResult.Clean
        } else {
            CheckResult.Detected(matches.map { Evidence(id, CONFIDENCE, "marker:$it") })
        }
    }

    companion object {
        const val CONFIDENCE = 0.85f

        /** Obfuscated hooking-framework markers (Frida, Xposed/LSPosed, ART hook frameworks). */
        val MARKERS: List<String> = TextCodec.decodeList(
            "796d767b7e15676f706c7a7b156c6a7d6c6b6d7e6b7a15736c6f706c7a7b1573767d786a721573767d736c6f" +
                "7b1573767d6d766d6a15656678766c74156c7e717b777070741573767d7a6f767c1573767d7b707d7d6615" +
                "6c777e7b7068777070741573767d68777e737a15667e77797e1573767d6f76717a",
            0x1F,
        )
    }
}
