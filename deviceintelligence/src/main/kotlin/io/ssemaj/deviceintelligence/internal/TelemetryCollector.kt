package io.ssemaj.deviceintelligence.internal

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.SystemClock
import android.util.Log
import io.ssemaj.deviceintelligence.AppContext
import io.ssemaj.deviceintelligence.DetectorReport
import io.ssemaj.deviceintelligence.DetectorStatus
import io.ssemaj.deviceintelligence.DeviceContext
import io.ssemaj.deviceintelligence.DeviceIntelligence
import io.ssemaj.deviceintelligence.ReportSummary
import io.ssemaj.deviceintelligence.Severity
import io.ssemaj.deviceintelligence.TELEMETRY_SCHEMA_VERSION
import io.ssemaj.deviceintelligence.TelemetryReport

/**
 * The single orchestrator that turns the registered list of
 * [Detector]s into one [TelemetryReport].
 *
 * The list is fixed at construction time. Adding a new detector =
 * one line in [defaultDetectors]. Nothing else in the codebase
 * needs to know it exists — not the public API, not the JSON
 * serializer, not the sample app.
 *
 * Detector ordering in the report mirrors registration order, but
 * the report is otherwise insensitive to ordering — every detector
 * runs and its result lands in [TelemetryReport.detectors] regardless
 * of what others did.
 */
internal object TelemetryCollector {

    private const val TAG = "DeviceIntelligence.Collector"

    /**
     * F10 needs to be addressable separately from the iteration list
     * because [collect] consults its post-evaluation [Fingerprint]
     * cache to populate [AppContext.buildVariant] and
     * [AppContext.libraryPluginVersion]. Keeping the same instance
     * means we don't re-decode.
     */
    private val apkIntegrity = ApkIntegrityDetector()

    private val defaultDetectors: List<Detector> = listOf(
        apkIntegrity,
        SelfProtectDetector,
        EmulatorProbe,
        ClonerDetector,
    )

    fun collect(context: Context): TelemetryReport {
        val started = SystemClock.elapsedRealtime()
        val nativeReady = runCatching { NativeBridge.isReady() }.getOrDefault(false)
        val appCtx = context.applicationContext
        val ctx = DetectorContext(
            applicationContext = appCtx,
            nativeReady = nativeReady,
        )

        val detectorReports = ArrayList<DetectorReport>(defaultDetectors.size)
        for (det in defaultDetectors) {
            val report = try {
                det.evaluate(ctx)
            } catch (t: Throwable) {
                Log.w(TAG, "detector ${det.id} threw — capturing as ERROR", t)
                errored(det.id, t, 0L)
            }
            detectorReports += report
        }

        val device = buildDeviceContext()
        val app = buildAppContext(appCtx, nativeReady)
        val summary = computeSummary(detectorReports)

        return TelemetryReport(
            schemaVersion = TELEMETRY_SCHEMA_VERSION,
            libraryVersion = DeviceIntelligence.VERSION,
            collectedAtEpochMs = System.currentTimeMillis(),
            collectionDurationMs = SystemClock.elapsedRealtime() - started,
            device = device,
            app = app,
            detectors = detectorReports,
            summary = summary,
        )
    }

    private fun buildDeviceContext(): DeviceContext = DeviceContext(
        manufacturer = Build.MANUFACTURER ?: "",
        model = Build.MODEL ?: "",
        sdkInt = Build.VERSION.SDK_INT,
        abi = (Build.SUPPORTED_ABIS?.firstOrNull() ?: "").ifEmpty { "unknown" },
        fingerprint = Build.FINGERPRINT ?: "",
    )

    private fun buildAppContext(context: Context, nativeReady: Boolean): AppContext {
        val pkg = context.packageName
        val apkPath = context.applicationInfo?.sourceDir
        val installer = readInstaller(context)
        val signers = if (nativeReady && apkPath != null) {
            runCatching { NativeBridge.apkSignerCertHashes(apkPath) }
                .getOrNull()?.toList().orEmpty()
        } else emptyList()

        // Reuse F10's already-decoded fingerprint when available
        // rather than re-decoding from disk a second time.
        val fp = apkIntegrity.lastDecodedFingerprint()

        return AppContext(
            packageName = pkg,
            apkPath = apkPath,
            installerPackage = installer,
            signerCertSha256 = signers,
            buildVariant = fp?.variantName,
            libraryPluginVersion = fp?.pluginVersion,
        )
    }

    @Suppress("DEPRECATION")
    private fun readInstaller(context: Context): String? {
        val pm: PackageManager = context.packageManager
        val pkg = context.packageName
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                pm.getInstallSourceInfo(pkg).installingPackageName
            } else {
                pm.getInstallerPackageName(pkg)
            }
        } catch (t: Throwable) {
            null
        }
    }

    private fun computeSummary(reports: List<DetectorReport>): ReportSummary {
        var total = 0
        val bySev = LinkedHashMap<Severity, Int>().apply {
            // Keep iteration order stable for serialisation.
            for (s in Severity.values()) put(s, 0)
        }
        val byKind = LinkedHashMap<String, Int>()
        val withFindings = ArrayList<String>()
        val inconclusive = ArrayList<String>()
        val errored = ArrayList<String>()
        for (r in reports) {
            when (r.status) {
                DetectorStatus.OK -> if (r.findings.isNotEmpty()) {
                    withFindings += r.id
                    for (f in r.findings) {
                        total++
                        bySev[f.severity] = (bySev[f.severity] ?: 0) + 1
                        byKind[f.kind] = (byKind[f.kind] ?: 0) + 1
                    }
                }
                DetectorStatus.INCONCLUSIVE -> inconclusive += r.id
                DetectorStatus.ERROR -> errored += r.id
            }
        }
        return ReportSummary(
            totalFindings = total,
            findingsBySeverity = bySev,
            findingsByKind = byKind,
            detectorsWithFindings = withFindings,
            detectorsInconclusive = inconclusive,
            detectorsErrored = errored,
        )
    }
}
