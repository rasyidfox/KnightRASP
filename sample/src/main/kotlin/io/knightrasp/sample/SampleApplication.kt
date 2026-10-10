package io.knightrasp.sample

import android.app.Application
import io.knightrasp.Rasp
import io.knightrasp.config.Environment
import io.knightrasp.config.Mode
import io.knightrasp.config.Policies
import io.knightrasp.config.RaspConfig
import io.knightrasp.config.RaspRules
import io.knightrasp.model.Level
import io.knightrasp.telemetry.queue.ExecutorTelemetryScheduler
import io.knightrasp.telemetry.queue.FileTelemetryStore
import io.knightrasp.telemetry.queue.QueuedTelemetrySink
import io.knightrasp.telemetry.queue.TelemetryQueue
import io.knightrasp.telemetry.queue.TelemetryQueueConfig
import java.io.File

class SampleApplication : Application() {

    override fun onCreate() {
        super.onCreate()

        Rasp.init(
            this,
            RaspConfig(
                // Mode PROTECT + kebijakan senyap: begitu terdeteksi ancaman level HIGH
                // ke atas (root/Frida/integritas), aplikasi ditutup paksa tanpa log,
                // dialog, atau error apa pun (native exit_group).
                mode = Mode.PROTECT,
                environment = Environment.RELEASE,
                policy = Policies.silentKillOn(Level.HIGH),
                telemetry = createTelemetry(),
                // Contoh rules inline. Di produksi, muat lewat SignedRulesLoader:
                //   SignedRulesLoader(RuleEnvelopeVerifier(PUBLIC_KEY))
                //       .loadFromUrl("https://backend.example/rules.json", ...)
                rules = RaspRules(
                    version = 1,
                    disabledChecks = setOf("env.developer_options"),
                    confidenceScale = mapOf("integrity.installer" to 0.5f),
                ),
                // Log SDK sepenuhnya senyap. Set true hanya saat debugging lokal.
                debugLogging = false,
            ),
        )
    }

    private fun createTelemetry(): QueuedTelemetrySink {
        val uploader = io.knightrasp.telemetry.queue.TelemetryUploader { _ ->
            // Ganti dengan backend Anda. Tidak ada log: mode senyap.
            true
        }
        return QueuedTelemetrySink(
            queue = TelemetryQueue(
                store = FileTelemetryStore(File(filesDir, "knightrasp-telemetry.jsonl")),
                maxEvents = 100,
            ),
            uploader = uploader,
            scheduler = ExecutorTelemetryScheduler(),
            config = TelemetryQueueConfig(minLevel = io.knightrasp.model.Level.LOW),
        )
    }
}
