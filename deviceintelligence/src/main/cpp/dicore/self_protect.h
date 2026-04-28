// self_protect.h — code-region watchdog for libdicore.so.
//
// Snapshots the FNV-1a hash of every executable PT_LOAD segment in
// libdicore.so (capped to a tunable byte budget per segment), plus
// any caller-registered RX region (the F12 trampoline page, future
// allocations, etc.). Re-verifies on demand from a Kotlin-side timer.
//
// Threat model:
//   In-process attacker who patches our native code at runtime to
//   neutralise the detector — e.g. NOPs out find_central_directory,
//   rewrites apkSignerCertHashes to return a baked-in "good" cert.
//   Our v2/v3 parser can't catch that; this watchdog can.
//
// Non-goals:
//   This module is purely DETECTION. It does not re-apply the original
//   bytes on tamper, because the gap between snapshot and re-check is
//   wide enough that the attacker may already have exploited the window.
//   Re-patching would only paper over the symptom and risks racing the
//   attacker's own re-patch.

#pragma once

#include <cstddef>
#include <cstdint>

namespace dicore {
namespace selfprotect {

// Take a fresh snapshot of libdicore.so's executable segments.
// Idempotent — clears any prior state and rebuilds from scratch.
// Safe to call from any thread; protected by an internal mutex.
void snapshot();

// Register an additional region for hash verification. Caller MUST
// guarantee [start, start+len) stays mapped and readable for the
// lifetime of the snapshot (or until the next snapshot() reset).
// `label` is copied; no lifetime requirement on the caller's pointer.
void add_region(uintptr_t start, std::size_t len, const char* label);

// Re-hash every registered region and compare with the baseline.
// Returns the number of regions whose current hash diverges from
// the snapshot. 0 means clean.
int verify();

// Number of registered regions; diagnostic only.
int region_count();

// Read-only introspection of region [idx]. Returns false if [idx] is
// out of range. On success, fills *[start], *[len], *[baseline_hash]
// with the snapshot values, and copies up to label_capacity-1 bytes
// of the label (NUL-terminated) into [label_buf]. Any out-pointer
// may be NULL if the caller doesn't need that field.
//
// Used by the UI introspection layer to render the per-region card.
bool region_at(int idx,
               uintptr_t* start,
               std::size_t* len,
               uint64_t* baseline_hash,
               char* label_buf,
               std::size_t label_capacity);

}  // namespace selfprotect
}  // namespace dicore
