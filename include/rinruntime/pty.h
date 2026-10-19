/* SPDX-License-Identifier: MIT */
#ifndef RINRUNTIME_PTY_H
#define RINRUNTIME_PTY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RIN_RUNTIME_PTY_VERSION UINT32_C(0x00010000)
#define RIN_RUNTIME_PTY_PATH_CAPACITY UINT32_C(32)

typedef struct RinRuntimePtyV1 {
    uint32_t struct_size;
    uint32_t version;
    int32_t master_fd;
    int32_t slave_fd;
    char slave_path[RIN_RUNTIME_PTY_PATH_CAPACITY];
} RinRuntimePtyV1;

/* Opens /dev/ptmx, unlocks its slave, and opens the corresponding
 * /dev/pts/N path. Returns 0 or -1 with errno set. */
int rinruntime_pty_open(RinRuntimePtyV1* pty);

/* Closes any still-owned descriptors and invalidates the record. */
int rinruntime_pty_close(RinRuntimePtyV1* pty);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_PTY_H */
