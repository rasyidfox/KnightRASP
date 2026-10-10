package io.knightrasp.telemetry.queue

import io.knightrasp.model.Category
import io.knightrasp.model.Evidence
import io.knightrasp.model.Level
import org.json.JSONArray
import org.json.JSONObject

/** Serialisasi [TelemetryEvent] ke satu baris JSON (JSON Lines). */
class TelemetryEventCodec {

    fun encode(event: TelemetryEvent): String {
        val root = JSONObject()
        root.put("id", event.id)
        root.put("ts", event.timestampMs)
        root.put("level", event.level.name)
        root.put("score", event.score.toDouble())
        root.put("sdk", event.sdkVersion)

        val categories = JSONObject()
        event.categories.forEach { (category, value) -> categories.put(category.name, value.toDouble()) }
        root.put("categories", categories)

        val evidence = JSONArray()
        event.evidence.forEach { item ->
            evidence.put(
                JSONObject()
                    .put("rule", item.ruleId)
                    .put("confidence", item.confidence.toDouble())
                    .put("detail", item.detail)
            )
        }
        root.put("evidence", evidence)
        return root.toString()
    }

    fun decode(line: String): TelemetryEvent? = try {
        val root = JSONObject(line)
        val categories = mutableMapOf<Category, Float>()
        root.optJSONObject("categories")?.let { json ->
            json.keys().forEach { key ->
                runCatching { Category.valueOf(key) }
                    .getOrNull()
                    ?.let { categories[it] = json.optDouble(key, 0.0).toFloat() }
            }
        }
        val evidence = mutableListOf<Evidence>()
        root.optJSONArray("evidence")?.let { array ->
            for (index in 0 until array.length()) {
                val item = array.optJSONObject(index) ?: continue
                evidence += Evidence(
                    ruleId = item.optString("rule"),
                    confidence = item.optDouble("confidence", 0.0).toFloat(),
                    detail = item.optString("detail").takeIf { it.isNotEmpty() && it != "null" },
                )
            }
        }
        TelemetryEvent(
            id = root.optString("id"),
            timestampMs = root.optLong("ts"),
            level = runCatching { Level.valueOf(root.optString("level")) }.getOrDefault(Level.NONE),
            score = root.optDouble("score", 0.0).toFloat(),
            categories = categories,
            evidence = evidence,
            sdkVersion = root.optString("sdk"),
        )
    } catch (_: Exception) {
        null
    }
}
