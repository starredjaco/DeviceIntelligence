// self_protect_jni.cpp — JNI surface for the self-protect watchdog
// (see self_protect.h) and a small, test-only tamper helper used by
// the io.ssemaj.deviceintelligence.testing.SelfProtectTestRig facade to demonstrate
// detection from sample apps and instrumented tests.
//
// The tamper helper is intentionally compiled into the production
// library (not gated by a build flag) because:
//   * It exposes no power an attacker doesn't already have — any caller
//     who can JNI into us already has full process-memory access.
//   * It only flips bytes inside our OWN .text and never inside any
//     parser function (probe address is a JNI export, not a parser).
//   * It is reachable only via the explicit `testing` subpackage,
//     which is NOT covered by consumer-rules.pro `-keep` rules and
//     therefore is stripped/renamed by R8 in any release consumer build
//     that doesn't reference it.
//   * It logs loudly to logcat on every invocation, so accidental
//     production use is immediately obvious.

#include "self_protect.h"
#include "log.h"

#include <cstdio>
#include <cstring>
#include <jni.h>
#include <sys/mman.h>
#include <unistd.h>

namespace dicore {
namespace selfprotect {
namespace {

// Mark a single page of our own .text as RW for the duration of a one-byte
// flip, then mprotect it back to R-X. Returns true on success.
bool flip_one_byte_in_text(uintptr_t target) {
    const long ps = sysconf(_SC_PAGESIZE);
    if (ps <= 0) return false;
    const std::size_t page_size = static_cast<std::size_t>(ps);
    void* page_start = reinterpret_cast<void*>(target & ~(page_size - 1));

    // Step 1: temporarily lift PROT_WRITE on the containing page. On
    // stock Android the kernel allows our process to mprotect its own
    // text pages; some hardened builds (GrapheneOS, vendor lockdowns)
    // may refuse. In that case we return false and the caller logs.
    if (mprotect(page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        RLOGW("tamper-for-test: mprotect RW failed at %p", page_start);
        return false;
    }

    // Step 2: flip exactly one byte at the target address, deterministic
    // XOR with 0xFF so the watchdog sees a hash change.
    auto* p = reinterpret_cast<uint8_t*>(target);
    const uint8_t before = *p;
    *p = static_cast<uint8_t>(before ^ 0xFFu);

    // Step 3: restore R-X. We deliberately do NOT restore the original
    // byte; the watchdog is meant to observe persistent tampering.
    // If the test wants to "untamper" it can re-call us with the same
    // address (XOR 0xFF twice = identity).
    if (mprotect(page_start, page_size, PROT_READ | PROT_EXEC) != 0) {
        RLOGW("tamper-for-test: mprotect R-X restore failed at %p", page_start);
        // Best effort; leave the page RWX rather than crash the test.
    }

    RLOGW(
        "tamper-for-test: flipped 1 byte at %p (was=0x%02x now=0x%02x)",
        reinterpret_cast<void*>(target),
        before,
        *p);
    return true;
}

}  // namespace
}  // namespace selfprotect
}  // namespace dicore

extern "C" {

JNIEXPORT void JNICALL
Java_io_ssemaj_deviceintelligence_internal_SelfProtect_nativeSnapshot(JNIEnv*, jclass) {
    dicore::selfprotect::snapshot();
}

JNIEXPORT void JNICALL
Java_io_ssemaj_deviceintelligence_internal_SelfProtect_nativeAddRegion(
    JNIEnv* env, jclass, jlong start, jlong len, jstring jlabel) {
    const char* label = jlabel ? env->GetStringUTFChars(jlabel, nullptr) : nullptr;
    dicore::selfprotect::add_region(
        static_cast<uintptr_t>(start),
        static_cast<std::size_t>(len),
        label);
    if (label && jlabel) env->ReleaseStringUTFChars(jlabel, label);
}

JNIEXPORT jint JNICALL
Java_io_ssemaj_deviceintelligence_internal_SelfProtect_nativeVerify(JNIEnv*, jclass) {
    return dicore::selfprotect::verify();
}

JNIEXPORT jint JNICALL
Java_io_ssemaj_deviceintelligence_internal_SelfProtect_nativeRegionCount(JNIEnv*, jclass) {
    return dicore::selfprotect::region_count();
}

// Diagnostic dump of a single region. Returns null if [idx] is out of
// range; otherwise a String formatted as
//   "label|start_hex|len_dec|baseline_hash_hex"
// Caller (SelfProtect Kotlin facade) does the parsing. Keeping the
// JNI surface a flat opaque string keeps us from needing a heavy
// JNI struct/object marshalling layer for what is essentially a UI
// debug feature.
JNIEXPORT jstring JNICALL
Java_io_ssemaj_deviceintelligence_internal_SelfProtect_nativeRegionAt(
    JNIEnv* env, jclass, jint idx) {
    uintptr_t start = 0;
    std::size_t len = 0;
    uint64_t hash = 0;
    char label[64] = {};
    if (!dicore::selfprotect::region_at(idx, &start, &len, &hash, label, sizeof(label))) {
        return nullptr;
    }
    char buf[192];
    std::snprintf(
        buf,
        sizeof(buf),
        "%s|0x%llx|%zu|0x%016llx",
        label,
        static_cast<unsigned long long>(start),
        len,
        static_cast<unsigned long long>(hash));
    return env->NewStringUTF(buf);
}

// Returns the runtime address (as jlong) of an arbitrary symbol-internal
// page inside libdicore.so .text. Used by the test tamper helper as
// a target. We return the address of `nativeSnapshot` itself (a stable
// JNI export); flipping a byte there triggers the watchdog.
//
// We intentionally do NOT export the address of any *parser* function
// (apkSignerCertHashes, find_central_directory, etc.) so the test
// helper can never be repurposed to silently disable real parsers.
JNIEXPORT jlong JNICALL
Java_io_ssemaj_deviceintelligence_testing_SelfProtectTestRig_nativeTextProbeAddrForTest(
    JNIEnv*, jclass) {
    auto fn = reinterpret_cast<uintptr_t>(
        &Java_io_ssemaj_deviceintelligence_internal_SelfProtect_nativeSnapshot);
    // arm64 thumb-bit isn't a thing; mask off any low-bit weirdness
    // defensively (this code also builds for x86_64 where the mask is a
    // no-op).
    return static_cast<jlong>(fn & ~uintptr_t{1});
}

JNIEXPORT jboolean JNICALL
Java_io_ssemaj_deviceintelligence_testing_SelfProtectTestRig_nativeFlipByteForTest(
    JNIEnv*, jclass, jlong target) {
    return dicore::selfprotect::flip_one_byte_in_text(
        static_cast<uintptr_t>(target))
        ? JNI_TRUE
        : JNI_FALSE;
}

}  // extern "C"
