/* SPDX-License-Identifier: MIT */
/* Local one-shot physical consent for crash diagnostics. */

#ifndef RINRUNTIME_CRASH_CONSENT_H
#define RINRUNTIME_CRASH_CONSENT_H

#include <stdint.h>

#include <rin/crash_service.h>

#define RIN_CRASH_CONSENT_CALL_VERSION UINT16_C(1)
#define RIN_CRASH_CONSENT_CALL_REQUEST UINT16_C(1)
#define RIN_CRASH_CONSENT_CALL_TAKE    UINT16_C(2)
#define RIN_CRASH_CONSENT_CALL_CONSUME UINT16_C(3)
#define RIN_CRASH_CONSENT_CALL_CANCEL  UINT16_C(4)

typedef struct RinCrashConsentCallV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t operation;
    uint32_t flags;
    int32_t result;
    int32_t socket_fd;
    uint32_t reserved0;
    uint64_t request_id;
    uint64_t request_generation;
    RinCrashConsentProofV1 proof;
    uint64_t reserved[1];
} RinCrashConsentCallV1;

#ifdef __cplusplus
extern "C" {
#endif

/* Calls the kernel broker through the local 32-bit or native syscall ABI. */
int rin_crash_consent_call(RinCrashConsentCallV1* call);
int rin_crash_consent_request(
    int socket_fd, uint64_t request_id, uint64_t* request_generation);
int rin_crash_consent_take(
    int socket_fd, uint64_t request_id, uint64_t request_generation,
    RinCrashConsentProofV1* proof);
int rin_crash_consent_consume(
    int accepted_socket_fd, const RinCrashConsentProofV1* proof);
int rin_crash_consent_cancel(
    int socket_fd, uint64_t request_id, uint64_t request_generation);

#ifdef __cplusplus
}
static_assert(sizeof(RinCrashConsentCallV1) == 176u,
              "RinCrashConsentCallV1 ABI drift");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinCrashConsentCallV1) == 176u,
               "RinCrashConsentCallV1 ABI drift");
#endif

#endif /* RINRUNTIME_CRASH_CONSENT_H */
