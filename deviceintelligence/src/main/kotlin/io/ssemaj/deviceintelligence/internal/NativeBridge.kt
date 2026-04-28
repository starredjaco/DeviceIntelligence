package io.ssemaj.deviceintelligence.internal

/**
 * Thin JNI surface for the native dicore library.
 *
 * All entry points are intentionally low-level: they return raw arrays so
 * the JNI side stays trivial and so we never construct Java collections
 * inside C++ (which is a routine source of leaks and crashes). Kotlin
 * call sites (e.g. [ApkIntegrityDetector]) adapt these into proper
 * collections.
 *
 * The library name is `dicore`; ABI filters in `:deviceintelligence/build.gradle.kts`
 * restrict it to arm64-v8a and x86_64.
 */
internal object NativeBridge {

    @Volatile
    private var loaded: Boolean = false

    @Volatile
    private var loadError: Throwable? = null

    init {
        try {
            System.loadLibrary("dicore")
            loaded = true
        } catch (t: Throwable) {
            loadError = t
        }
    }

    /** Returns true if libdicore.so loaded and SHA backend is bound. */
    fun isReady(): Boolean = loaded && runCatching { nativeReady() }.getOrDefault(false)

    /** Throwable from the [System.loadLibrary] attempt, if any. */
    fun loadError(): Throwable? = loadError

    @JvmStatic
    external fun nativeReady(): Boolean

    /**
     * Walks the APK at [path] and returns a flat alternating array
     * `[name0, hash0, name1, hash1, ...]` of central-directory entries.
     * Returns null if the APK can't be opened or the central directory
     * can't be found.
     */
    @JvmStatic
    external fun apkEntries(path: String): Array<String>?

    /**
     * Returns SHA-256 hex strings of each v2/v3 signer certificate in the
     * APK at [path]. Returns null if the APK can't be opened, an empty
     * array if no v2/v3 signing block is present.
     */
    @JvmStatic
    external fun apkSignerCertHashes(path: String): Array<String>?
}
