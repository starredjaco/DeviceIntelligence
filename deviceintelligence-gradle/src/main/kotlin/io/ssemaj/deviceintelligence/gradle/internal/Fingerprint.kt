package io.ssemaj.deviceintelligence.gradle.internal

/**
 * Build-time data model the plugin emits and the runtime later consumes
 * (after F7 encrypts it and F9 decrypts it back).
 *
 * Schema is versioned so that older blobs decoded by a newer runtime can be
 * detected and handled gracefully. Bump [SCHEMA_VERSION] whenever a field is
 * added, removed, or its semantics change.
 */
internal data class Fingerprint(
    val schemaVersion: Int,
    val builtAtEpochMs: Long,
    val pluginVersion: String,
    val variantName: String,
    val applicationId: String,
    /** SHA-256 hex of each signer certificate (DER) found in the keystore. */
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
        const val SCHEMA_VERSION: Int = 1
        const val ASSET_PATH: String = "assets/io.ssemaj/fingerprint.bin"
        val DEFAULT_IGNORED_ENTRY_PREFIXES: List<String> = listOf("META-INF/")
        val DEFAULT_IGNORED_ENTRIES: List<String> = listOf(ASSET_PATH)
    }
}
