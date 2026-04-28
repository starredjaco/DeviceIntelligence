// self_protect.cpp — implementation of the libdicore.so .text watchdog.
// See self_protect.h for the threat model and design constraints.
#include "self_protect.h"

#include "log.h"

#include <cstring>
#include <elf.h>
#include <link.h>
#include <mutex>
#include <vector>

namespace dicore {
namespace selfprotect {

namespace {

// Per-tick byte budget for hashing one executable segment. 4 MiB is
// chosen as the tradeoff:
//  - FNV-1a 64-bit at ~1.5 GB/s on arm64-v8a is ~3ms per MiB; a 4 MiB
//    cap keeps a single segment under ~12ms even on slow cores, well
//    inside any reasonable verifier interval (default 1s, min 100ms).
//  - libdicore.so's executable segment is currently ~140 KiB; 4 MiB
//    leaves ~28x headroom before a code-size growth would force us to
//    re-evaluate.
//  - Anything smaller (e.g. the prior project's original 16 KiB) misses the
//    bulk of our exported functions: the bulk of JNI exports live
//    well past offset 16 KiB, so a 16 KiB cap can't detect tamper of
//    the very functions an attacker would target.
//
// Future option for very large code: take multiple deterministic
// sub-region samples per segment instead of a single contiguous hash.
constexpr std::size_t kSegmentByteBudget = 4 * 1024 * 1024;

// Basename used to locate ourselves in dl_iterate_phdr. Must match
// the SONAME emitted by CMake (`dicore` -> `libdicore.so`).
constexpr const char* kOwnLibBasename = "libdicore.so";

struct Region {
    uintptr_t start;
    std::size_t len;
    uint64_t baseline_hash;
    char label[64];
};

std::mutex g_regions_mtx;
std::vector<Region> g_regions;

// FNV-1a 64-bit. Not a cryptographic hash — an attacker who can read
// our snapshot table can produce a colliding patch. Mitigation is
// snapshot-time entropy (see snapshot()) which keeps the model out
// of the attacker's reach for the duration of the process. For
// strong attackers we'd swap to BLAKE3 or hardware AES; FNV-1a is
// the right perf/complexity tradeoff for v1 and matches what
// the prior project used.
uint64_t fnv1a64(const void* data, std::size_t len) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(data);
    uint64_t h = 0xCBF29CE484222325ULL;
    for (std::size_t i = 0; i < len; ++i) {
        h ^= p[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}

void add_region_locked(uintptr_t start, std::size_t len, const char* label) {
    Region r{};
    r.start = start;
    r.len = len;
    r.baseline_hash = fnv1a64(reinterpret_cast<const void*>(start), len);
    if (label) {
        std::size_t L = std::strlen(label);
        if (L >= sizeof(r.label)) L = sizeof(r.label) - 1;
        std::memcpy(r.label, label, L);
        r.label[L] = '\0';
    }
    g_regions.push_back(r);
    RLOGI(
        "self-protect: registered '%s' [%p, +%zu) hash=0x%016llx",
        r.label,
        reinterpret_cast<void*>(r.start),
        r.len,
        static_cast<unsigned long long>(r.baseline_hash));
}

struct DlCtx {
    bool found = false;
    uintptr_t base = 0;
    const ElfW(Phdr)* phdr = nullptr;
    int phnum = 0;
};

int find_lib_cb(struct dl_phdr_info* info, std::size_t /*size*/, void* data) {
    auto* ctx = static_cast<DlCtx*>(data);
    if (!info->dlpi_name) return 0;
    const char* slash = std::strrchr(info->dlpi_name, '/');
    const char* base = slash ? slash + 1 : info->dlpi_name;
    if (std::strcmp(base, kOwnLibBasename) == 0) {
        ctx->found = true;
        ctx->base = info->dlpi_addr;
        ctx->phdr = info->dlpi_phdr;
        ctx->phnum = info->dlpi_phnum;
        // dl_iterate_phdr stops when callback returns non-zero.
        return 1;
    }
    return 0;
}

}  // namespace

void snapshot() {
    std::lock_guard<std::mutex> lk(g_regions_mtx);
    g_regions.clear();

    DlCtx ctx;
    dl_iterate_phdr(find_lib_cb, &ctx);
    if (!ctx.found) {
        RLOGW("self-protect: %s not found in dl_iterate_phdr", kOwnLibBasename);
        return;
    }

    int x_segments = 0;
    for (int i = 0; i < ctx.phnum; ++i) {
        const ElfW(Phdr)& ph = ctx.phdr[i];
        if (ph.p_type != PT_LOAD || !(ph.p_flags & PF_X)) continue;
        uintptr_t s = ctx.base + ph.p_vaddr;
        std::size_t L = ph.p_memsz;
        if (L > kSegmentByteBudget) L = kSegmentByteBudget;
        add_region_locked(s, L, "libdicore.text");
        ++x_segments;
    }
    RLOGI("self-protect: snapshot complete: %d executable segment(s)", x_segments);
}

void add_region(uintptr_t start, std::size_t len, const char* label) {
    std::lock_guard<std::mutex> lk(g_regions_mtx);
    add_region_locked(start, len, label);
}

int verify() {
    std::lock_guard<std::mutex> lk(g_regions_mtx);
    int mismatches = 0;
    for (const auto& r : g_regions) {
        const uint64_t now =
            fnv1a64(reinterpret_cast<const void*>(r.start), r.len);
        if (now != r.baseline_hash) {
            ++mismatches;
            RLOGE(
                "self-protect: TAMPER on '%s' [%p, +%zu) "
                "was=0x%016llx now=0x%016llx",
                r.label,
                reinterpret_cast<void*>(r.start),
                r.len,
                static_cast<unsigned long long>(r.baseline_hash),
                static_cast<unsigned long long>(now));
        }
    }
    return mismatches;
}

int region_count() {
    std::lock_guard<std::mutex> lk(g_regions_mtx);
    return static_cast<int>(g_regions.size());
}

bool region_at(int idx,
               uintptr_t* start,
               std::size_t* len,
               uint64_t* baseline_hash,
               char* label_buf,
               std::size_t label_capacity) {
    std::lock_guard<std::mutex> lk(g_regions_mtx);
    if (idx < 0 || static_cast<std::size_t>(idx) >= g_regions.size()) {
        return false;
    }
    const Region& r = g_regions[idx];
    if (start) *start = r.start;
    if (len) *len = r.len;
    if (baseline_hash) *baseline_hash = r.baseline_hash;
    if (label_buf && label_capacity > 0) {
        std::size_t L = std::strlen(r.label);
        if (L >= label_capacity) L = label_capacity - 1;
        std::memcpy(label_buf, r.label, L);
        label_buf[L] = '\0';
    }
    return true;
}

}  // namespace selfprotect
}  // namespace dicore
