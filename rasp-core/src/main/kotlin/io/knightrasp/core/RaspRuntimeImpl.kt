package io.knightrasp.core

import android.app.Activity
import android.app.Application
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.Process
import io.knightrasp.RaspListener
import io.knightrasp.RaspRuntime
import io.knightrasp.check.RaspCheck
import io.knightrasp.check.RaspContext
import io.knightrasp.config.Mode
import io.knightrasp.config.MultiProcessMode
import io.knightrasp.config.RaspConfig
import io.knightrasp.model.Level
import io.knightrasp.model.RaspError
import io.knightrasp.model.ThreatAssessment
import io.knightrasp.model.Trigger
import io.knightrasp.probe.Probes
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.cancellation.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Default [RaspRuntime] implementation.
 *
 * - `init` must complete quickly: no I/O, the first scan is scheduled to the background.
 * - Async scans are coalesced: when one scan is running, subsequent calls are
 *   skipped (not queued).
 * - Listeners and responses are always invoked on the main thread.
 * - Fail-open: all internal errors are reported through listeners and never
 *   thrown to the caller.
 */
class RaspRuntimeImpl(
    private val probes: Probes,
    private val checks: List<RaspCheck>,
    private val clock: () -> Long = System::currentTimeMillis,
) : RaspRuntime {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Check execution scope; separate so stragglers do not hold up the scan. */
    private val workScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val listeners = CopyOnWriteArrayList<RaspListener>()
    private val mainHandler = Handler(Looper.getMainLooper())
    private val scanMutex = Mutex()

    @Volatile
    private var config: RaspConfig = RaspConfig()

    @Volatile
    private var initialized = false

    @Volatile
    private var active = false

    @Volatile
    private var appPackageName: String = ""

    private var engine: ScanEngine? = null
    private var executor: ResponseExecutor? = null
    private var appRef: Application? = null
    private var lifecycleCallbacks: Application.ActivityLifecycleCallbacks? = null

    override fun init(app: Application, config: RaspConfig) {
        if (initialized) {
            return
        }
        validate(config)?.let(::reportError)
        this.config = config
        this.appPackageName = app.packageName
        this.appRef = app
        RaspLog.setEnabled(config.debugLogging)

        val processName: String? = app.applicationInfo?.processName
        val mainProcess = processName == null || processName == app.packageName
        if (config.multiProcess == MultiProcessMode.MAIN_ONLY && !mainProcess) {
            initialized = true
            if (RaspLog.ENABLED) {
                RaspLog.d("Not the main process; the RASP engine is inactive in this process.")
            }
            return
        }

        val rules = RuleTuner.activeRules(config, clock())
        engine = ScanEngine(
            checks = CheckRegistry(checks).activeFor(config, rules),
            scorer = Scorer(RuleTuner.effectiveThresholds(config, rules)),
            cache = TtlCache(clock),
            workScope = workScope,
            evidenceTuner = RuleTuner.evidenceTuner(rules),
        )
        executor = ResponseExecutor(
            mode = config.mode,
            telemetry = config.telemetry,
            hostActions = config.hostActions,
            killProcess = {
                probes.native?.shutdown() ?: Process.killProcess(Process.myPid())
            },
        )
        probes.native?.watchdog(
            enabled = config.watchdogEnabled,
            killOnEvidence = config.mode == Mode.PROTECT,
            intervalMs = config.watchdogIntervalMs.coerceIn(500L, Int.MAX_VALUE.toLong()).toInt(),
        )
        registerForegroundCallbacks(app)
        active = true
        initialized = true

        scan(Trigger.ON_INIT)
    }

    override fun scan(trigger: Trigger) {
        if (!initialized) {
            reportError(RaspError(RaspError.Code.NOT_INITIALIZED, "Rasp.init has not been called."))
            return
        }
        if (!active) {
            return
        }
        scope.launch {
            if (!scanMutex.tryLock()) {
                if (RaspLog.ENABLED) {
                    RaspLog.d("Scan skipped: another scan is still running.")
                }
                return@launch
            }
            try {
                runScan()
            } finally {
                scanMutex.unlock()
            }
        }
    }

    override fun scanSync(timeoutMs: Long): ThreatAssessment {
        if (!initialized || !active) {
            return ThreatAssessment.unknown(clock())
        }
        val currentEngine = engine ?: return ThreatAssessment.unknown(clock())
        val context = buildContext()
        return try {
            val assessment = runBlocking {
                withTimeoutOrNull(timeoutMs) {
                    withContext(Dispatchers.IO) {
                        currentEngine.scan(context, useCache = false, onCheckFailure = ::reportCheckFailure)
                    }
                }
            }
            if (assessment == null) {
                reportError(
                    RaspError(RaspError.Code.SCAN_TIMEOUT, "scanSync exceeded the ${timeoutMs}ms limit.")
                )
                ThreatAssessment.unknown(clock())
            } else {
                assessment
            }
        } catch (t: Throwable) {
            if (t is CancellationException) throw t
            reportError(RaspError(RaspError.Code.ENGINE_FAILURE, "scanSync failed.", t))
            ThreatAssessment.unknown(clock())
        }
    }

    override fun addListener(listener: RaspListener) {
        listeners.addIfAbsent(listener)
    }

    override fun removeListener(listener: RaspListener) {
        listeners.remove(listener)
    }

    override fun shutdown() {
        scope.cancel()
        workScope.cancel()
        appRef?.let { app ->
            lifecycleCallbacks?.let(app::unregisterActivityLifecycleCallbacks)
        }
        lifecycleCallbacks = null
        listeners.clear()
        active = false
        initialized = false
    }

    private suspend fun runScan() {
        val currentEngine = engine ?: return
        val context = buildContext()

        val assessment = try {
            currentEngine.scan(context, useCache = true, onCheckFailure = ::reportCheckFailure)
        } catch (t: CancellationException) {
            throw t
        } catch (t: Throwable) {
            reportError(RaspError(RaspError.Code.ENGINE_FAILURE, "Scan failed.", t))
            return
        }

        // Safety kill: in PROTECT mode a HIGH+ verdict is also reported to the native
        // layer, which terminates the process from its watchdog even if the Kotlin
        // response path (policy/executor) was tampered with.
        if (config.mode == Mode.PROTECT && assessment.level >= Level.HIGH) {
            probes.native?.signalRisk(true)
        }

        val responses = try {
            config.policy.responsesFor(assessment)
        } catch (t: Throwable) {
            reportError(RaspError(RaspError.Code.INVALID_CONFIG, "Policy threw an exception.", t))
            emptyList()
        }

        mainHandler.post {
            executor?.execute(responses, assessment) { error -> reportError(error) }
            listeners.forEach { listener ->
                runCatching { listener.onAssessment(assessment) }
                    .onFailure {
                        if (RaspLog.ENABLED) {
                            RaspLog.w("Listener threw an exception.", it)
                        }
                    }
            }
        }
    }

    private fun buildContext(): RaspContext = object : RaspContext {
        override val config: RaspConfig get() = this@RaspRuntimeImpl.config
        override val probes: Probes = this@RaspRuntimeImpl.probes
        override val packageName: String get() = appPackageName
        override val nowMs: Long get() = clock()
    }

    private fun registerForegroundCallbacks(app: Application) {
        val callbacks = object : Application.ActivityLifecycleCallbacks {
            private val foregroundReported = AtomicBoolean(false)

            override fun onActivityStarted(activity: Activity) {
                if (foregroundReported.compareAndSet(false, true)) {
                    scan(Trigger.ON_FOREGROUND)
                }
            }

            override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {}
            override fun onActivityResumed(activity: Activity) {}
            override fun onActivityPaused(activity: Activity) {}
            override fun onActivityStopped(activity: Activity) {}
            override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) {}
            override fun onActivityDestroyed(activity: Activity) {}
        }
        app.registerActivityLifecycleCallbacks(callbacks)
        lifecycleCallbacks = callbacks
    }

    private fun reportCheckFailure(checkId: String, cause: Throwable) {
        if (RaspLog.ENABLED) {
            RaspLog.w("Check $checkId failed: ${cause.message}")
        }
    }

    private fun reportError(error: RaspError) {
        if (RaspLog.ENABLED) {
            RaspLog.e(error.message, error.cause)
        }
        mainHandler.post {
            listeners.forEach { listener ->
                runCatching { listener.onError(error) }
                    .onFailure {
                        if (RaspLog.ENABLED) {
                            RaspLog.w("Listener.onError threw an exception.", it)
                        }
                    }
            }
        }
    }

    private fun validate(config: RaspConfig): RaspError? {
        val t = config.thresholds
        val inRange = t.low in 0f..1f && t.medium in 0f..1f && t.high in 0f..1f
        val ordered = t.low <= t.medium && t.medium <= t.high
        return if (inRange && ordered) {
            null
        } else {
            RaspError(RaspError.Code.INVALID_CONFIG, "Invalid thresholds: $t")
        }
    }
}
