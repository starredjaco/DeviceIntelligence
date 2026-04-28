#pragma once

#include <cstddef>
#include <cstdint>
#include <sys/types.h>

namespace dicore::sys {

// Raw syscall wrappers. Each goes directly through `svc #0` (aarch64) or
// `syscall` (x86_64); they do not pass through any libc PLT entry, so an
// attacker who has hooked libc's `open`, `mmap`, `read`, etc. cannot observe
// or rewrite our reads.
//
// Errors are surfaced as -1 with a positive errno written into errno_out
// (we don't rely on the libc thread-local errno because that itself is
// reachable from libc-side hooks).

int    raw_openat(int dirfd, const char* path, int flags, int mode, int* errno_out);
int    raw_close(int fd);
ssize_t raw_read_full(int fd, void* buf, size_t count, int* errno_out);
off_t  raw_lseek(int fd, off_t offset, int whence, int* errno_out);
int    raw_fstat_size(int fd, off_t* out_size, int* errno_out);
void*  raw_mmap_readonly(size_t length, int fd, off_t offset, int* errno_out);
int    raw_munmap(void* addr, size_t length);

} // namespace dicore::sys
