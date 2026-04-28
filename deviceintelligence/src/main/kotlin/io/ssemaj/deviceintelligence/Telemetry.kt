package io.ssemaj.deviceintelligence

/**
 * The single, structured output of a DeviceIntelligence run.
 *
 * DeviceIntelligence is a *telemetry* layer — it collects facts about the runtime
 * environment of the host app and hands them back as a serialisable
 * report. It does NOT decide whether the app should keep running,
 * shut down, lock the user out, or anything else. That decision
 * belongs to the consumer's backend or in-app policy layer, working
 * off of (typically) [toJson] uploaded from the device.
 *
 * The schema is intentionally flat and stable. Every value below is
 * either a primitive, a string, or a list/map of those — no enums or
 * sealed-class hierarchies leak into the wire format. This means:
 *  - Backends can parse the JSON with any vanilla JSON library.
 *  - Adding a new detector / finding kind is purely additive: it
 *    appears as an extra entry in [detectors] / a new value of
 *    [Finding.kind], without breaking older consumers.
 *  - [schemaVersion] is bumped only on breaking changes.
 *
 * Consumers MUST treat [Finding.kind] and [Finding.severity] as the
 * stable contract; [Finding.details] is opaque diagnostic data whose
 * keys may change without a schema bump.
 */
public data class TelemetryReport(
    /** Wire-format version. Currently 1; bumped only on breaking changes. */
    public val schemaVersion: Int,

    /** DeviceIntelligence library version that produced this report. */
    public val libraryVersion: String,

    /** Wall-clock when collection finished. UTC milliseconds. */
    public val collectedAtEpochMs: Long,

    /** Total wall-clock the [io.ssemaj.deviceintelligence.DeviceIntelligence.collect] call took, including all detectors. */
    public val collectionDurationMs: Long,

    /** Hardware / OS facts about the device the report was collected from. */
    public val device: DeviceContext,

    /** Identity facts about the app instance the report was collected from. */
    public val app: AppContext,

    /** One entry per registered detector, in registration order. */
    public val detectors: List<DetectorReport>,

    /** Pre-computed roll-ups; backends can ignore and recompute themselves. */
    public val summary: ReportSummary,
) {
    /** Renders this report as a deterministic, pretty-printed JSON string. */
    public fun toJson(): String =
        io.ssemaj.deviceintelligence.internal.TelemetryJson.encode(this)
}

/**
 * Stable wire-format version. Incremented only when an existing
 * field's meaning changes or a field is removed. Adding new optional
 * fields, new detector ids, or new [Finding.kind] values is NOT a
 * breaking change.
 */
public const val TELEMETRY_SCHEMA_VERSION: Int = 1

/**
 * Hardware / OS context. Mirrors [android.os.Build] but trimmed to
 * fields that are stable, useful for cohorting, and not PII.
 */
public data class DeviceContext(
    public val manufacturer: String,
    public val model: String,
    public val sdkInt: Int,
    public val abi: String,
    /**
     * `Build.FINGERPRINT`. Useful for grouping reports by ROM build
     * (a rooted ROM often has a hand-edited fingerprint).
     */
    public val fingerprint: String,
)

/**
 * App-instance context. These are facts the consumer knows about
 * itself, but having them on the report side simplifies backend
 * grouping and removes an entire class of mismatched-metadata bugs.
 */
public data class AppContext(
    public val packageName: String,
    public val apkPath: String?,
    public val installerPackage: String?,
    /** SHA-256 hex of every signer cert observed at runtime, in the order F10 returns them. */
    public val signerCertSha256: List<String>,
    /** AGP build variant the running APK was compiled from (e.g. "debug"). May be null if the F10 fingerprint hasn't been decoded. */
    public val buildVariant: String?,
    /** deviceintelligence-gradle plugin version that produced the baked fingerprint. May be null if the fingerprint hasn't been decoded. */
    public val libraryPluginVersion: String?,
)

/**
 * Output of a single [Detector]'s run. Always present in
 * [TelemetryReport.detectors] for every registered detector, even
 * if it found nothing — absence and "found nothing" are different
 * facts and we report both.
 */
public data class DetectorReport(
    /** Stable detector id, e.g. `"F10.apk_integrity"`. Unique within a [TelemetryReport]. */
    public val id: String,

    /** [DetectorStatus.OK] is the only status that allows [findings] to be trusted. */
    public val status: DetectorStatus,

    /** Wall-clock the detector took. */
    public val durationMs: Long,

    /** Findings produced by this detector. Empty when [status] != OK or when the detector ran cleanly. */
    public val findings: List<Finding>,

    /** Set when [status] == [DetectorStatus.INCONCLUSIVE]; otherwise null. Stable identifier suitable for backend grouping. */
    public val inconclusiveReason: String? = null,

    /** Set when [status] == [DetectorStatus.ERROR]; otherwise null. Free-form diagnostic. */
    public val errorMessage: String? = null,
)

/**
 * One concrete piece of evidence produced by a detector.
 *
 * Stable contract for backends:
 *  - [kind]: stable identifier for grouping and alerting.
 *  - [severity]: DeviceIntelligence's *suggested* severity. Backends MAY override
 *    per their own policy; severity is never a verdict.
 *  - [subject]: free-form identifier of what was inspected (a package
 *    name, an APK entry, a region label). Useful for grouping and
 *    showing in UIs.
 *  - [message]: human-readable one-liner, deterministic per
 *    (`kind`, `details`). Suitable as the headline in an alert.
 *
 * Opaque (unstable) contract:
 *  - [details]: a string-keyed bag of diagnostic information whose
 *    keys may change without a schema bump. Useful for forensics,
 *    NOT suitable as a programmatic contract surface.
 */
public data class Finding(
    public val kind: String,
    public val severity: Severity,
    public val subject: String?,
    public val message: String,
    public val details: Map<String, String>,
)

/**
 * Suggested severity tier for a [Finding]. Backends MAY treat this
 * as policy input but DeviceIntelligence itself never acts on severity — that's
 * not DeviceIntelligence's job.
 */
public enum class Severity {
    /** Informational; expected on most devices (e.g. running on a beta-channel ROM). */
    LOW,

    /** Possibly suspicious; could be benign on some devices (e.g. installer is sideload). */
    MEDIUM,

    /** Strong tampering signal that warrants attention (e.g. running on an emulator). */
    HIGH,

    /** Direct evidence of an active attack channel (e.g. running inside an app cloner, foreign code in process). */
    CRITICAL,
}

/**
 * Outcome status for a [DetectorReport].
 */
public enum class DetectorStatus {
    /** Detector ran cleanly; [DetectorReport.findings] reflects what it found (possibly empty). */
    OK,

    /** Detector tried but couldn't reach a conclusion (missing native lib, unreadable file, format skew). [DetectorReport.inconclusiveReason] explains. */
    INCONCLUSIVE,

    /** Detector threw an unexpected exception. [DetectorReport.errorMessage] has details. */
    ERROR,
}

/**
 * Pre-computed roll-ups derived from [TelemetryReport.detectors].
 * Provided as a convenience so a backend doesn't have to recompute
 * every common stat. Always consistent with the underlying detector
 * reports.
 */
public data class ReportSummary(
    public val totalFindings: Int,
    public val findingsBySeverity: Map<Severity, Int>,
    public val findingsByKind: Map<String, Int>,
    public val detectorsWithFindings: List<String>,
    public val detectorsInconclusive: List<String>,
    public val detectorsErrored: List<String>,
)
