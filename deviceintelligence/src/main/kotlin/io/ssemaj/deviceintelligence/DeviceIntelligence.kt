package io.ssemaj.deviceintelligence

import android.content.Context
import io.ssemaj.deviceintelligence.internal.SelfProtect
import io.ssemaj.deviceintelligence.internal.TelemetryCollector

/**
 * Public entry-point for DeviceIntelligence.
 *
 * DeviceIntelligence is a *telemetry* layer: it collects facts about the runtime
 * environment of the host app (APK integrity, in-process code
 * tampering, emulator characteristics, app-cloner indicators) and
 * hands them back as a single structured [TelemetryReport]. It does
 * NOT decide whether the app should keep running, prompt the user,
 * lock data, or anything else. That decision belongs to the
 * consumer's backend or in-app policy layer.
 *
 * Two modes of operation:
 *  - **One-shot collection** ([collect] / [collectJson]): runs every
 *    detector once, returns a snapshot. Cheap (~tens of ms), safe to
 *    call from any thread, results NOT cached at this layer (each
 *    detector caches what it sensibly can; an outer cache should
 *    live in the consumer if needed).
 *  - **Continuous self-protection** ([startSelfProtect]): a
 *    background watchdog over `libdicore.so`'s executable
 *    segments. Fires the registered [SelfProtectListener] in real
 *    time on any drift. Independent of the one-shot collection;
 *    the watchdog's accumulated state ALSO surfaces in the next
 *    [collect] under the `F11.self_protect` detector.
 */
public object DeviceIntelligence {

    public const val VERSION: String = "0.1.0-dev"

    /**
     * Run every detector and return a [TelemetryReport] reflecting
     * the current runtime state.
     *
     * Cost: typically ~tens of milliseconds (a single APK ZIP walk
     * dominates). Safe to call from any thread; for production use
     * call off the main thread.
     */
    public fun collect(context: Context): TelemetryReport =
        TelemetryCollector.collect(context.applicationContext)

    /**
     * Convenience wrapper around [collect] that hands back the
     * report serialised to its canonical JSON form. Equivalent to
     * `collect(context).toJson()` but shorter at the call site.
     */
    public fun collectJson(context: Context): String =
        collect(context).toJson()

    // ---- F11: native code-region watchdog (real-time) ----------------------

    /**
     * Start the F11 watchdog. Periodically re-hashes
     * `libdicore.so`'s executable segments (and any region added
     * via [registerSelfProtectRegion]); fires [listener] on any
     * drift.
     *
     * Idempotent; the second call is a no-op (interval and listener
     * latch on first call). For best security take the snapshot AS
     * EARLY AS POSSIBLE — the manifest-merged
     * [io.ssemaj.deviceintelligence.internal.DeviceIntelligenceInitProvider] does this at
     * `ContentProvider.onCreate`, before any third-party SDK init.
     *
     * The watchdog's accumulated state ALSO surfaces in the
     * `F11.self_protect` entry of the next [collect] report — so a
     * consumer that doesn't want real-time response can skip this
     * call entirely and just rely on telemetry collection.
     *
     * @param intervalMs verifier tick interval. Coerced to >= 100ms.
     * @param listener   real-time callback invoked on the verifier
     *                   thread (never the UI thread) when one or more
     *                   regions drift. Optional.
     */
    public fun startSelfProtect(
        intervalMs: Long = SelfProtect.DEFAULT_INTERVAL_MS,
        listener: SelfProtectListener? = null,
    ) {
        if (listener != null) SelfProtect.setListener(listener)
        SelfProtect.start(intervalMs)
    }

    /** Stop the F11 watchdog. The snapshot is retained. */
    public fun stopSelfProtect() {
        SelfProtect.stop()
    }

    /**
     * Register an additional executable region (e.g. a JIT
     * trampoline page or a third-party library you want covered)
     * for hash verification. Caller MUST keep the bytes mapped and
     * readable for the lifetime of the snapshot.
     */
    public fun registerSelfProtectRegion(start: Long, len: Long, label: String) {
        SelfProtect.addRegion(start, len, label)
    }
}
