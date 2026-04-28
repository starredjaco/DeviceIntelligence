package io.ssemaj.deviceintelligence.testing

import io.ssemaj.deviceintelligence.internal.NativeBridge

/**
 * Test-only helpers for exercising the F11 native code-region watchdog
 * end-to-end from a sample app or instrumented test.
 *
 * **NOT FOR PRODUCTION USE.** This object exposes a primitive that
 * deliberately patches `libdicore.so` `.text` at runtime — useful
 * for proving the watchdog detects tampering, but obviously a foot-gun
 * if invoked outside a test environment.
 *
 * Why it lives in the AAR (not as a separate test artifact):
 *  - The native code it drives must compile *into* `libdicore.so`
 *    so the JNI symbols resolve. Splitting into a separate `.so`
 *    would double the surface and complicate the build.
 *  - In a release consumer build, R8 strips this entire `testing`
 *    subpackage as long as the consumer never references it (no
 *    `-keep` rule covers it).
 *  - The native helpers it dispatches to are intentionally limited:
 *    they can flip bytes inside our own `.text` only, never anywhere
 *    else. They expose no power an attacker doesn't already have, and
 *    they log loudly to logcat on every invocation.
 */
public object SelfProtectTestRig {

    /**
     * Returns a stable address inside `libdicore.so` `.text` (the
     * entry of an internal JNI function) that callers can pass to
     * [flipOneByteOfText] as a tamper target. Never returns 0 on a
     * successfully-loaded library.
     */
    public fun probeAddressInOwnText(): Long {
        ensureNative()
        return nativeTextProbeAddrForTest()
    }

    /**
     * Flips one byte at [target] inside `libdicore.so` `.text` (XOR
     * with 0xFF). Returns true if the page could be made writable and
     * the flip went through. Calling twice with the same address is an
     * idempotent restore (XOR 0xFF twice = identity).
     *
     * Strongly intended for paired use with [probeAddressInOwnText];
     * passing arbitrary addresses outside our own text is undefined
     * behaviour and will crash the process.
     */
    public fun flipOneByteOfText(target: Long): Boolean {
        ensureNative()
        return nativeFlipByteForTest(target)
    }

    private fun ensureNative() {
        check(NativeBridge.isReady()) {
            "libdicore.so not loaded: ${NativeBridge.loadError()?.message}"
        }
    }

    @JvmStatic private external fun nativeTextProbeAddrForTest(): Long
    @JvmStatic private external fun nativeFlipByteForTest(target: Long): Boolean
}
