package io.ssemaj.deviceintelligence.internal

import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import io.ssemaj.deviceintelligence.SelfProtectListener
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Watchdog over libdicore.so's executable segments, plus any
 * caller-registered RX page. Detects in-process attackers who patch
 * our native code at runtime to neutralise the F3-F5 parsers or the
 * F10 detector.
 *
 * Lifecycle:
 *   1. [snapshot] — fingerprint the current bytes. Should be called as
 *      early as possible (the F11-wired init provider does this on
 *      ContentProvider.onCreate, before any third-party SDK init).
 *   2. [start] — kick off the periodic verifier on a dedicated
 *      [HandlerThread]. Idempotent. Takes a fresh snapshot if none has
 *      been taken yet, so callers can skip [snapshot] if they don't
 *      care about precise snapshot timing.
 *   3. [stop] — quiesce the verifier. The snapshot is retained so a
 *      later [start] resumes against the same baseline.
 *
 * Failure mode:
 *   On every tick the native verifier returns the number of regions
 *   whose hash drifted; if non-zero, the registered [listener] is
 *   invoked on the verifier thread. We deliberately do NOT touch the
 *   process state on tamper — re-applying the original bytes only
 *   papers over the symptom, and the gap between snapshot and re-check
 *   is wide enough that the attacker may already have exploited the
 *   window (see the prior project commit history for the reasoning).
 */
internal object SelfProtect {

    private const val TAG = "DeviceIntelligence.SelfProtect"

    @Volatile
    private var listener: SelfProtectListener? = null

    private val running = AtomicBoolean(false)
    private var thread: HandlerThread? = null
    private var handler: Handler? = null

    @Volatile
    private var intervalMs: Long = DEFAULT_INTERVAL_MS

    // Tamper stats — surfaced via SelfProtectDetector into telemetry.
    // Updated from both the verifier loop AND any call into
    // [verifyOnce], so a single drift seen via either channel gets
    // counted exactly once even when both observe it.
    private val tamperEventCount = AtomicLong(0)
    private val firstTamperAtEpochMs = AtomicLong(-1)
    private val lastTamperAtEpochMs = AtomicLong(-1)
    @Volatile private var lastTamperRegionCount: Int = 0

    @JvmStatic private external fun nativeSnapshot()
    @JvmStatic private external fun nativeAddRegion(start: Long, len: Long, label: String)
    @JvmStatic private external fun nativeVerify(): Int
    @JvmStatic private external fun nativeRegionCount(): Int

    /** Take (or retake) the baseline snapshot. Idempotent. */
    fun snapshot() {
        ensureNativeReady()
        nativeSnapshot()
        Log.i(TAG, "snapshot: ${nativeRegionCount()} region(s)")
    }

    /**
     * Register an additional region for hash verification. Caller MUST
     * keep [start, start+len) mapped + readable for the lifetime of
     * the snapshot (or until the next [snapshot] reset).
     */
    fun addRegion(start: Long, len: Long, label: String) {
        ensureNativeReady()
        nativeAddRegion(start, len, label)
    }

    fun setListener(l: SelfProtectListener?) {
        listener = l
    }

    /**
     * Start the periodic verifier on a dedicated daemon thread.
     * Idempotent; the second call returns immediately. Takes a fresh
     * snapshot if [regionCount] is currently zero.
     */
    fun start(intervalMs: Long = DEFAULT_INTERVAL_MS) {
        if (!running.compareAndSet(false, true)) return
        ensureNativeReady()
        this.intervalMs = intervalMs.coerceAtLeast(MIN_INTERVAL_MS)
        if (nativeRegionCount() == 0) snapshot()

        val ht = HandlerThread("DeviceIntelligence-SelfProtect").apply { start() }
        thread = ht
        val h = Handler(ht.looper)
        handler = h
        h.postDelayed(verifyLoop, this.intervalMs)
        Log.i(
            TAG,
            "verifier started: interval=${this.intervalMs}ms regions=${nativeRegionCount()}",
        )
    }

    fun stop() {
        if (!running.compareAndSet(true, false)) return
        handler?.removeCallbacks(verifyLoop)
        thread?.quitSafely()
        handler = null
        thread = null
        Log.i(TAG, "verifier stopped")
    }

    fun regionCount(): Int = if (NativeBridge.isReady()) nativeRegionCount() else 0

    fun isRunning(): Boolean = running.get()

    fun currentIntervalMs(): Long = intervalMs

    private val verifyLoop = object : Runnable {
        override fun run() {
            if (!running.get()) return
            val mismatches = try {
                nativeVerify()
            } catch (t: Throwable) {
                Log.w(TAG, "nativeVerify threw", t)
                0
            }
            if (mismatches > 0) {
                recordTamperObservation(mismatches)
                runCatching { listener?.onTamper(mismatches) }
                    .onFailure { Log.w(TAG, "listener.onTamper threw", it) }
            }
            handler?.postDelayed(this, intervalMs)
        }
    }

    /**
     * Run the native verifier ONCE, off the watchdog cadence.
     * Returns the number of regions that have drifted. Called from
     * [SelfProtectDetector] at telemetry-collection time so the
     * snapshot is fresh even when the watchdog isn't running.
     *
     * Updates the same tamper stats the watchdog does — a single
     * drift observed via either path is counted once.
     */
    fun verifyOnce(): Int {
        if (!NativeBridge.isReady()) return 0
        if (nativeRegionCount() == 0) return 0
        val mismatches = try {
            nativeVerify()
        } catch (t: Throwable) {
            Log.w(TAG, "verifyOnce.nativeVerify threw", t)
            return 0
        }
        if (mismatches > 0) recordTamperObservation(mismatches)
        return mismatches
    }

    private fun recordTamperObservation(mismatchedRegions: Int) {
        val now = System.currentTimeMillis()
        tamperEventCount.incrementAndGet()
        firstTamperAtEpochMs.compareAndSet(-1L, now)
        lastTamperAtEpochMs.set(now)
        lastTamperRegionCount = mismatchedRegions
        Log.e(TAG, "TAMPER detected: $mismatchedRegions region(s) drifted")
    }

    /** Tamper stats as observed since this process started. */
    data class TamperStats(
        val totalEvents: Long,
        val firstAtEpochMs: Long, // -1 if never observed
        val lastAtEpochMs: Long,  // -1 if never observed
        val lastRegionCount: Int, // 0 if never observed
    )

    fun tamperStats(): TamperStats = TamperStats(
        totalEvents = tamperEventCount.get(),
        firstAtEpochMs = firstTamperAtEpochMs.get(),
        lastAtEpochMs = lastTamperAtEpochMs.get(),
        lastRegionCount = lastTamperRegionCount,
    )

    /**
     * Forces NativeBridge's static-init to run, so libdicore.so is
     * loaded and our `external` hooks resolve. Safe to call from any
     * thread; idempotent.
     */
    private fun ensureNativeReady() {
        if (!NativeBridge.isReady()) {
            error("libdicore.so not loaded: ${NativeBridge.loadError()?.message}")
        }
    }

    const val DEFAULT_INTERVAL_MS: Long = 1000L
    const val MIN_INTERVAL_MS: Long = 100L
}
