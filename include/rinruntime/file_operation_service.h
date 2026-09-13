/* SPDX-License-Identifier: MIT */
/* Authenticated, user-scoped durable FileOperation service protocol. */

#ifndef RINRUNTIME_FILE_OPERATION_SERVICE_H
#define RINRUNTIME_FILE_OPERATION_SERVICE_H

#include <stdint.h>

#include "file_operation.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RINRUNTIME_FILE_OPERATION_SERVICE_VERSION 1u
#define RINRUNTIME_FILE_OPERATION_SERVICE_PATH "/run/rin/fileoperationd.sock"
/* The broker endpoint is deliberately distinct from the ordinary application
 * endpoint.  No authorization ticket is accepted on SERVICE_PATH. */
#define RINRUNTIME_FILE_OPERATION_SERVICE_BROKER_PATH \
    "/run/rin/fileoperationd-broker.sock"
#define RINRUNTIME_FILE_OPERATION_SERVICE_ENTRY_LIMIT \
    RINRUNTIME_FILE_OPERATION_ENTRY_LIMIT

/* A protected-location mutation is never authorized by a client-controlled
 * flag.  A privileged broker obtains this opaque, generation-bound ticket
 * from the kernel/object policy and passes it through the broker-only API in
 * fileoperationd.  The service rechecks the peer binding and asks the broker
 * to validate the ticket immediately before backend mutation. */
#define RINRUNTIME_FILE_OPERATION_SERVICE_AUTHORIZATION_VERSION 1u
#define RINRUNTIME_FILE_OPERATION_SERVICE_AUTHORIZATION_BYTES 32u
typedef struct RinRuntimeFileOperationServiceAuthorizationV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t operation;
    uint32_t owner_uid;
    uint64_t process_instance_cookie;
    uint64_t connection_id;
    uint64_t object_generation;
    uint8_t application_id[32];
    uint8_t capability[RINRUNTIME_FILE_OPERATION_SERVICE_AUTHORIZATION_BYTES];
    uint32_t reserved[2];
} RinRuntimeFileOperationServiceAuthorizationV1;

typedef enum RinRuntimeFileOperationServiceRequestKind {
    RINRUNTIME_FILE_OPERATION_SERVICE_SUBMIT = 1,
    RINRUNTIME_FILE_OPERATION_SERVICE_QUERY = 2,
    RINRUNTIME_FILE_OPERATION_SERVICE_CANCEL = 3,
    RINRUNTIME_FILE_OPERATION_SERVICE_UNDO = 4
} RinRuntimeFileOperationServiceRequestKind;

typedef enum RinRuntimeFileOperationServiceStatus {
    RINRUNTIME_FILE_OPERATION_SERVICE_OK = 0,
    RINRUNTIME_FILE_OPERATION_SERVICE_INVALID_ARGUMENT = -1,
    RINRUNTIME_FILE_OPERATION_SERVICE_UNAVAILABLE = -2,
    RINRUNTIME_FILE_OPERATION_SERVICE_BUSY = -3,
    RINRUNTIME_FILE_OPERATION_SERVICE_ACCESS_DENIED = -4,
    RINRUNTIME_FILE_OPERATION_SERVICE_NOT_FOUND = -5,
    RINRUNTIME_FILE_OPERATION_SERVICE_NOT_UNDOABLE = -6,
    RINRUNTIME_FILE_OPERATION_SERVICE_IO_FAILED = -7,
    RINRUNTIME_FILE_OPERATION_SERVICE_CONFLICT = -8
} RinRuntimeFileOperationServiceStatus;

typedef enum RinRuntimeFileOperationServiceJobState {
    RINRUNTIME_FILE_OPERATION_SERVICE_JOB_NONE = 0,
    RINRUNTIME_FILE_OPERATION_SERVICE_JOB_RUNNING = 1,
    RINRUNTIME_FILE_OPERATION_SERVICE_JOB_COMPLETED = 2,
    RINRUNTIME_FILE_OPERATION_SERVICE_JOB_CANCELLED = 3,
    RINRUNTIME_FILE_OPERATION_SERVICE_JOB_FAILED = 4,
    RINRUNTIME_FILE_OPERATION_SERVICE_JOB_UNDO_RUNNING = 5,
    RINRUNTIME_FILE_OPERATION_SERVICE_JOB_UNDONE = 6,
    RINRUNTIME_FILE_OPERATION_SERVICE_JOB_INTERRUPTED = 7
} RinRuntimeFileOperationServiceJobState;

#define RINRUNTIME_FILE_OPERATION_SERVICE_ENTRY_CLEANUP_ON_SUCCESS 0x00000001u
#define RINRUNTIME_FILE_OPERATION_SERVICE_ENTRY_CLEANUP_ON_FAILURE 0x00000002u
#define RINRUNTIME_FILE_OPERATION_SERVICE_ENTRY_RECREATE_CLEANUP_ON_UNDO_SUCCESS 0x00000004u
#define RINRUNTIME_FILE_OPERATION_SERVICE_ENTRY_CLEANUP_ON_UNDO_SUCCESS 0x00000008u
#define RINRUNTIME_FILE_OPERATION_SERVICE_ENTRY_FLAGS_KNOWN \
    (RINRUNTIME_FILE_OPERATION_SERVICE_ENTRY_CLEANUP_ON_SUCCESS | \
     RINRUNTIME_FILE_OPERATION_SERVICE_ENTRY_CLEANUP_ON_FAILURE | \
     RINRUNTIME_FILE_OPERATION_SERVICE_ENTRY_RECREATE_CLEANUP_ON_UNDO_SUCCESS | \
     RINRUNTIME_FILE_OPERATION_SERVICE_ENTRY_CLEANUP_ON_UNDO_SUCCESS)

typedef struct RinRuntimeFileOperationServiceHeaderV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t request_kind;
    uint64_t request_id;
    uint32_t payload_size;
    uint32_t flags;
    int32_t status;
    uint32_t reserved;
} RinRuntimeFileOperationServiceHeaderV1;

/* Wire entries own their path storage; no client pointer crosses the socket. */
typedef struct RinRuntimeFileOperationServiceEntryV1 {
    uint32_t kind;
    uint32_t flags;
    uint32_t link_source_index;
    uint32_t reserved;
    uint64_t size_bytes;
    char source_path[RINRUNTIME_FILE_OPERATION_PATH_MAX];
    char destination_path[RINRUNTIME_FILE_OPERATION_PATH_MAX];
    /* Optional state sidecar removed only under the selected cleanup rule. */
    char cleanup_path[RINRUNTIME_FILE_OPERATION_PATH_MAX];
} RinRuntimeFileOperationServiceEntryV1;

typedef struct RinRuntimeFileOperationServiceSubmitV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t operation;
    uint32_t conflict_policy;
    uint32_t entry_count;
    uint32_t reserved[2];
    /* Application-private, canonical state directory for the journal. */
    char state_directory[RINRUNTIME_FILE_OPERATION_PATH_MAX];
} RinRuntimeFileOperationServiceSubmitV1;

/* Fixed prefix for the broker-only submit wire payload.  Entries follow this
 * prefix in the same bounded array format as ordinary SUBMIT. */
#define RINRUNTIME_FILE_OPERATION_SERVICE_AUTHORIZED_SUBMIT_VERSION 1u
typedef struct RinRuntimeFileOperationServiceAuthorizedSubmitV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t reserved;
    RinRuntimeFileOperationServiceAuthorizationV1 authorization;
    RinRuntimeFileOperationServiceSubmitV1 submit;
} RinRuntimeFileOperationServiceAuthorizedSubmitV1;

typedef struct RinRuntimeFileOperationServiceControlV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t reserved0;
    uint64_t job_id; /* 0 means the authenticated caller's latest job. */
    char state_directory[RINRUNTIME_FILE_OPERATION_PATH_MAX];
} RinRuntimeFileOperationServiceControlV1;

typedef struct RinRuntimeFileOperationServiceReplyV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t job_state;
    uint64_t job_id;
    uint32_t percent;
    int32_t operation_result;
    uint64_t completed_bytes;
    uint64_t total_bytes;
    uint64_t completed_items;
    uint32_t entry_count;
    uint32_t reserved;
} RinRuntimeFileOperationServiceReplyV1;

typedef struct RinRuntimeFileOperationServiceClientV1 {
    int32_t socket_fd;
    uint32_t reserved;
    uint64_t next_request_id;
} RinRuntimeFileOperationServiceClientV1;

/* Broker clients are a separate type so ordinary application code cannot
 * accidentally select the privileged endpoint. */
typedef struct RinRuntimeFileOperationServiceBrokerClientV1 {
    int32_t socket_fd;
    uint32_t reserved;
    uint64_t next_request_id;
} RinRuntimeFileOperationServiceBrokerClientV1;

void rinruntime_file_operation_service_client_init(
    RinRuntimeFileOperationServiceClientV1* client);
void rinruntime_file_operation_service_client_close(
    RinRuntimeFileOperationServiceClientV1* client);
RinRuntimeFileOperationServiceStatus rinruntime_file_operation_service_submit(
    RinRuntimeFileOperationServiceClientV1* client,
    const RinRuntimeFileOperationServiceSubmitV1* request,
    const RinRuntimeFileOperationServiceEntryV1* entries,
    RinRuntimeFileOperationServiceReplyV1* reply_out);
RinRuntimeFileOperationServiceStatus rinruntime_file_operation_service_query(
    RinRuntimeFileOperationServiceClientV1* client,
    const RinRuntimeFileOperationServiceControlV1* request,
    RinRuntimeFileOperationServiceReplyV1* reply_out);
RinRuntimeFileOperationServiceStatus rinruntime_file_operation_service_cancel(
    RinRuntimeFileOperationServiceClientV1* client,
    const RinRuntimeFileOperationServiceControlV1* request,
    RinRuntimeFileOperationServiceReplyV1* reply_out);
RinRuntimeFileOperationServiceStatus rinruntime_file_operation_service_undo(
    RinRuntimeFileOperationServiceClientV1* client,
    const RinRuntimeFileOperationServiceControlV1* request,
    RinRuntimeFileOperationServiceReplyV1* reply_out);

void rinruntime_file_operation_service_broker_client_init(
    RinRuntimeFileOperationServiceBrokerClientV1* client);
void rinruntime_file_operation_service_broker_client_close(
    RinRuntimeFileOperationServiceBrokerClientV1* client);
RinRuntimeFileOperationServiceStatus
rinruntime_file_operation_service_submit_authorized(
    RinRuntimeFileOperationServiceBrokerClientV1* client,
    const RinRuntimeFileOperationServiceSubmitV1* request,
    const RinRuntimeFileOperationServiceEntryV1* entries,
    const RinRuntimeFileOperationServiceAuthorizationV1* authorization,
    RinRuntimeFileOperationServiceReplyV1* reply_out);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_FILE_OPERATION_SERVICE_H */


