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
                // PROTECT mode + silent policy: as soon as a HIGH-level threat is detected
                // or above (root/Frida/integrity), the app is force-closed with no log,
                // dialog, or error of any kind (native exit_group).
                mode = Mode.PROTECT,
                environment = Environment.RELEASE,
                policy = Policies.silentKillOn(Level.HIGH),
                telemetry = createTelemetry(),
                // Example inline rules. In production, load them via SignedRulesLoader:
                //   SignedRulesLoader(RuleEnvelopeVerifier(PUBLIC_KEY))
                //       .loadFromUrl("https://backend.example/rules.json", ...)
                rules = RaspRules(
                    version = 1,
                    disabledChecks = setOf("env.developer_options"),
                    confidenceScale = mapOf("integrity.installer" to 0.5f),
                ),
                // SDK logging is fully silent. Set true only for local debugging.
                debugLogging = false,
            ),
        )

        // Key attestation example (send the chain to your backend for verification):
        //
        // Rasp.requestKeyAttestation(serverNonce) { result ->
        //     if (result != null) backend.verifyKeyAttestation(result.certificateChain)
        // }
    }

    private fun createTelemetry(): QueuedTelemetrySink {
        val uploader = io.knightrasp.telemetry.queue.TelemetryUploader { _ ->
            // Replace with your own backend. No logging: silent mode.
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
