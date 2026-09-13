/* SPDX-License-Identifier: MIT */
#ifndef RINRUNTIME_CRASH_H
#define RINRUNTIME_CRASH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RINRUNTIME_CRASH_API_VERSION 1u
#define RINRUNTIME_CRASH_MESSAGE_BYTES 256u
#define RINRUNTIME_CRASH_DIGEST_BYTES 32u

typedef enum RinRuntimeCrashKind {
    RINRUNTIME_CRASH_USER_FAILURE = 1u,
    RINRUNTIME_CRASH_RECOVERY_AVAILABLE = 2u
} RinRuntimeCrashKind;

typedef struct RinRuntimeCrashSummaryV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t kind;
    uint32_t message_size;
    uint32_t flags;
    uint64_t package_generation;
    uint8_t package_digest[RINRUNTIME_CRASH_DIGEST_BYTES];
    char message[RINRUNTIME_CRASH_MESSAGE_BYTES];
    uint64_t reserved[2];
} RinRuntimeCrashSummaryV1;

/* Validates a redacted summary. It never parses or exposes process memory. */
int rinruntime_crash_summary_validate(
    const RinRuntimeCrashSummaryV1* summary);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_CRASH_H */
