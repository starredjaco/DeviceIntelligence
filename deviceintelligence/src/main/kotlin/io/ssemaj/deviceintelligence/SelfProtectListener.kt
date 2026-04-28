package io.ssemaj.deviceintelligence

/**
 * Callback for the F11 native code-region watchdog
 * ([DeviceIntelligence.startSelfProtect]).
 *
 * Invoked from a background thread (a dedicated [android.os.HandlerThread]
 * named `DeviceIntelligence-SelfProtect`) on every verifier tick where one or more
 * registered regions have a different hash than at snapshot time.
 *
 * Implementations MUST be fast and non-blocking — they run on the same
 * thread that performs the next hash verification. Heavy work
 * (telemetry posts, kill-switch enforcement) should be dispatched to
 * a different executor.
 *
 * The listener is NOT invoked on a clean tick; absence of a call does
 * NOT prove tamper-free. Use [DeviceIntelligence.startSelfProtect] return value or
 * driver-side polling if you need a heartbeat signal.
 */
public fun interface SelfProtectListener {

    /**
     * @param mismatchedRegionCount how many distinct registered regions
     *        had a hash drift on the most recent tick. Always > 0.
     */
    public fun onTamper(mismatchedRegionCount: Int)
}
