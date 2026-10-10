package io.knightrasp.sample

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import io.knightrasp.Rasp
import io.knightrasp.RaspListener
import io.knightrasp.model.RaspError
import io.knightrasp.model.ThreatAssessment
import io.knightrasp.model.Trigger

class MainActivity : Activity(), RaspListener {

    private lateinit var statusView: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(48, 48, 48, 48)
        }
        statusView = TextView(this).apply {
            text = "Menunggu hasil scan..."
        }
        val scanButton = Button(this).apply {
            text = "Scan sekarang"
            setOnClickListener { Rasp.scan(Trigger.ON_DEMAND) }
        }
        layout.addView(statusView)
        layout.addView(scanButton)
        setContentView(layout)

        Rasp.addListener(this)
        Rasp.scan(Trigger.ON_DEMAND)
    }

    override fun onDestroy() {
        Rasp.removeListener(this)
        super.onDestroy()
    }

    override fun onAssessment(result: ThreatAssessment) {
        statusView.text = buildString {
            appendLine("Level: ${result.level}")
            appendLine("Score: ${format(result.score)}")
            appendLine("Evidence: ${result.evidence.size}")
            result.categories.entries.forEach { (category, score) ->
                appendLine("  $category: ${format(score)}")
            }
            result.evidence.take(5).forEach {
                appendLine("  - ${it.ruleId} (${format(it.confidence)})")
            }
        }
    }

    override fun onError(error: RaspError) {
        statusView.text = "Error ${error.code}: ${error.message}"
    }

    private fun format(value: Float): String = "%.2f".format(value)
}
