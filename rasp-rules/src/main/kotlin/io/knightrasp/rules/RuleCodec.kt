package io.knightrasp.rules

import io.knightrasp.config.RaspRules
import io.knightrasp.config.Thresholds
import org.json.JSONObject

/** Parser/encoder data-only untuk isi `payload` rules. */
object RuleCodec {

    fun parse(payloadJson: String): RaspRules {
        val root = JSONObject(payloadJson)
        require(root.has("version")) { "Rules tidak memiliki version" }

        return RaspRules(
            version = root.getInt("version"),
            issuedAtMs = root.optLong("issuedAtMs", 0L),
            expiresAtMs = if (root.has("expiresAtMs")) root.optLong("expiresAtMs") else null,
            disabledChecks = root.optJSONArray("disabledChecks")?.let { array ->
                (0 until array.length()).mapTo(LinkedHashSet()) { array.getString(it) }
            } ?: emptySet(),
            confidenceScale = root.optJSONObject("confidenceScale")?.let { scale ->
                buildMap {
                    scale.keys().forEach { key ->
                        put(key, scale.optDouble(key, 1.0).toFloat())
                    }
                }
            } ?: emptyMap(),
            thresholds = root.optJSONObject("thresholds")?.let { thresholds ->
                val defaults = Thresholds()
                Thresholds(
                    low = thresholds.optDouble("low", defaults.low.toDouble()).toFloat(),
                    medium = thresholds.optDouble("medium", defaults.medium.toDouble()).toFloat(),
                    high = thresholds.optDouble("high", defaults.high.toDouble()).toFloat(),
                )
            },
            signatureVerified = true,
        )
    }

    fun encode(rules: RaspRules): String {
        val root = JSONObject()
        root.put("version", rules.version)
        root.put("issuedAtMs", rules.issuedAtMs)
        rules.expiresAtMs?.let { root.put("expiresAtMs", it) }
        if (rules.disabledChecks.isNotEmpty()) {
            root.put("disabledChecks", rules.disabledChecks.toList())
        }
        if (rules.confidenceScale.isNotEmpty()) {
            val scale = JSONObject()
            rules.confidenceScale.forEach { (checkId, value) -> scale.put(checkId, value.toDouble()) }
            root.put("confidenceScale", scale)
        }
        rules.thresholds?.let { thresholds ->
            root.put(
                "thresholds",
                JSONObject()
                    .put("low", thresholds.low.toDouble())
                    .put("medium", thresholds.medium.toDouble())
                    .put("high", thresholds.high.toDouble()),
            )
        }
        return root.toString()
    }
}
