package io.ssemaj.deviceintelligence.internal

/**
 * Runtime mirror of the build-time `io.ssemaj.deviceintelligence.gradle.internal.Fingerprint`
 * data class. The two share an on-disk binary format ([FingerprintCodec]),
 * so any field added here must be added on the plugin side first (and the
 * format version bumped).
 *
 * Currently `internal`; [ApkIntegrityDetector] surfaces only the
 * relevant fields through the public `TelemetryReport` so downstream
 * consumers never depend on this type directly.
 */
internal data class Fingerprint(
    val schemaVersion: Int,
    val builtAtEpochMs: Long,
    val pluginVersion: String,
    val variantName: String,
    val applicationId: String,
    /** SHA-256 hex of each signer certificate (DER) baked at sign time. */
    val signerCertSha256: List<String>,
    /** Map of ZIP entry name -> SHA-256 hex of compressed body bytes. */
    val entries: Map<String, String>,
    /** Exact entry names the runtime must skip when comparing. */
    val ignoredEntries: List<String>,
    /** Entry-name prefixes the runtime must skip when comparing. */
    val ignoredEntryPrefixes: List<String>,
    /** Path prefix the device's installed APK must start with. */
    val expectedSourceDirPrefix: String,
    /** Acceptable installer package names (empty = anyone allowed). */
    val expectedInstallerWhitelist: List<String>,
) {
    companion object {
        /** Schema currently produced by the plugin. Must match plugin SCHEMA_VERSION. */
        const val SCHEMA_VERSION: Int = 1

        /**
         * Path of the encrypted blob inside the APK as written by F8's
         * [InstrumentApkTask][io.ssemaj.deviceintelligence.gradle.tasks.InstrumentApkTask].
         */
        const val ASSET_PATH: String = "assets/io.ssemaj.deviceintelligence/fingerprint.bin"
    }
}
