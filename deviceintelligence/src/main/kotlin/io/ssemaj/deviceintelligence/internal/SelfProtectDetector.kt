package io.ssemaj.deviceintelligence.internal

import android.os.SystemClock
import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.Finding
import io.ssemaj.deviceintelligence.Severity

/**
 * F11 — telemetry adapter for the [SelfProtect] watchdog.
 *
 * The watchdog itself is a long-lived background thread that fires
 * a real-time [io.ssemaj.deviceintelligence.SelfProtectListener] callback the
 * moment any of `libdicore.so`'s executable segments drift.
 * That's the right shape for in-process *response*.
 *
 * For *telemetry*, we want a snapshot of "what has the watchdog
 * observed so far?" plus a fresh re-verify at collection time so
 * the report reflects the absolute latest state of the bytes —
 * even when the watchdog isn't running. That snapshot is what
 * this detector produces.
 *
 * Findings produced:
 *  - `native_text_drift` — emitted iff [SelfProtect.tamperStats]
 *    shows at least one observation OR a fresh [SelfProtect.verifyOnce]
 *    sees current drift. CRITICAL severity (active in-process
 *    patching is unambiguous).
 *  - No finding when nothing has ever drifted and the live verify
 *    comes back clean.
 *
 * Status semantics:
 *  - INCONCLUSIVE if the native lib never loaded (verify is
 *    impossible) or if no regions have been registered (snapshot
 *    pre-flight).
 *  - OK in all other cases (with or without findings).
 */
internal object SelfProtectDetector : Detector {

    override val id: String = "F11.self_protect"

    override fun evaluate(ctx: DetectorContext): DetectorReport {
        val start = SystemClock.elapsedRealtime()
        fun dur(): Long = SystemClock.elapsedRealtime() - start

        if (!ctx.nativeReady) {
            return inconclusive(
                id, "native_not_ready",
                "dicore native lib not loaded", dur(),
            )
        }
        if (SelfProtect.regionCount() == 0) {
            return inconclusive(
                id, "no_regions_snapshotted",
                "SelfProtect snapshot has not been taken yet", dur(),
            )
        }

        val freshDrift = SelfProtect.verifyOnce()
        val stats = SelfProtect.tamperStats()

        val findings = if (stats.totalEvents == 0L && freshDrift == 0) {
            emptyList()
        } else {
            listOf(
                Finding(
                    kind = "native_text_drift",
                    severity = Severity.CRITICAL,
                    subject = "libdicore.text",
                    message = if (freshDrift > 0) {
                        "Native code region drift detected at collection time"
                    } else {
                        "Native code region drift was detected since process start"
                    },
                    details = mapOf(
                        "regions_currently_drifted" to freshDrift.toString(),
                        "tamper_event_count" to stats.totalEvents.toString(),
                        "first_event_at_epoch_ms" to stats.firstAtEpochMs.toString(),
                        "last_event_at_epoch_ms" to stats.lastAtEpochMs.toString(),
                        "last_event_region_count" to stats.lastRegionCount.toString(),
                        "watchdog_running" to SelfProtect.isRunning().toString(),
                        "watchdog_interval_ms" to SelfProtect.currentIntervalMs().toString(),
                        "regions_tracked" to SelfProtect.regionCount().toString(),
                    ),
                ),
            )
        }

        return ok(id, findings, dur())
    }
}
