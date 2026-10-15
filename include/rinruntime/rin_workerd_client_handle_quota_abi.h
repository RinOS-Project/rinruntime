/* SPDX-License-Identifier: MIT */
/* Private kernel/workerd wire ABI for client-owned response SHM handles. */
#ifndef RIN_SHARED_WORKERD_CLIENT_HANDLE_QUOTA_ABI_H
#define RIN_SHARED_WORKERD_CLIENT_HANDLE_QUOTA_ABI_H

#include <stdint.h>

#define RIN_WORKERD_HANDLE_QUOTA_SYSCALL_NUMBER UINT32_C(0x8F21)
#define RIN_WORKERD_HANDLE_QUOTA_SYSCALL_VERSION UINT32_C(1)
#define RIN_WORKERD_HANDLE_QUOTA_V1_VERSION UINT32_C(1)
#define RIN_WORKERD_HANDLE_QUOTA_V1_MAX_HANDLES UINT32_C(64)
#define RIN_WORKERD_HANDLE_QUOTA_V1_MAX_OWNER_HANDLES UINT32_C(16)

typedef enum RinWorkerdHandleQuotaV1Result {
    RIN_WORKERD_HANDLE_QUOTA_V1_OK = 0,
    RIN_WORKERD_HANDLE_QUOTA_V1_INVALID = -1,
    RIN_WORKERD_HANDLE_QUOTA_V1_NO_SPACE = -2,
    RIN_WORKERD_HANDLE_QUOTA_V1_DENIED = -3,
    RIN_WORKERD_HANDLE_QUOTA_V1_BUSY = -4,
    RIN_WORKERD_HANDLE_QUOTA_V1_STALE = -5
} RinWorkerdHandleQuotaV1Result;

typedef enum RinWorkerdHandleQuotaOperationV1 {
    RIN_WORKERD_HANDLE_QUOTA_OP_RESERVE = 1,
    RIN_WORKERD_HANDLE_QUOTA_OP_RELEASE = 2
} RinWorkerdHandleQuotaOperationV1;

typedef struct RinWorkerdClientHandleLeaseV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t active;
    uint32_t slot;
    uint64_t generation;
    uint64_t owner_id;
} RinWorkerdClientHandleLeaseV1;

typedef struct RinWorkerdHandleQuotaSyscallRequestV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t operation;
    uint32_t flags;
    uint64_t client_owner_id;
    RinWorkerdClientHandleLeaseV1 lease;
} RinWorkerdHandleQuotaSyscallRequestV1;

typedef struct RinWorkerdHandleQuotaSyscallResponseV1 {
    uint32_t struct_size;
    uint32_t version;
    uint32_t operation;
    uint32_t flags;
    int32_t status;
    uint32_t reserved0;
    RinWorkerdClientHandleLeaseV1 lease;
} RinWorkerdHandleQuotaSyscallResponseV1;

#if defined(__cplusplus)
static_assert(sizeof(RinWorkerdClientHandleLeaseV1) == 32u,
              "workerd client handle lease ABI drift");
static_assert(sizeof(RinWorkerdHandleQuotaSyscallRequestV1) == 56u,
              "workerd handle quota request ABI drift");
static_assert(sizeof(RinWorkerdHandleQuotaSyscallResponseV1) == 56u,
              "workerd handle quota response ABI drift");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(RinWorkerdClientHandleLeaseV1) == 32u,
               "workerd client handle lease ABI drift");
_Static_assert(sizeof(RinWorkerdHandleQuotaSyscallRequestV1) == 56u,
               "workerd handle quota request ABI drift");
_Static_assert(sizeof(RinWorkerdHandleQuotaSyscallResponseV1) == 56u,
               "workerd handle quota response ABI drift");
#endif

#endif /* RIN_SHARED_WORKERD_CLIENT_HANDLE_QUOTA_ABI_H */
