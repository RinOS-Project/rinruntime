/* SPDX-License-Identifier: MIT */
/* Small synchronous client used by RinRuntime's optional desktop bridge. */

#ifndef RINRUNTIME_ACCESSIBILITY_SERVICE_CLIENT_H
#define RINRUNTIME_ACCESSIBILITY_SERVICE_CLIENT_H

#include <stdint.h>

#include <rin/contract_abi.h>
#include <rin/accessibility_service.h>

typedef struct RinAccessibilityServiceClientV1 {
    int socket_fd;
    uint32_t reserved;
    uint64_t next_request_id;
    uint64_t pending_service_action_id;
} RinAccessibilityServiceClientV1;

#ifdef __cplusplus
extern "C" {
#endif

void rin_accessibility_service_client_init(RinAccessibilityServiceClientV1* client);
RinResultCode rin_accessibility_service_client_open(
    RinAccessibilityServiceClientV1* client);
void rin_accessibility_service_client_close(RinAccessibilityServiceClientV1* client);
RinResultCode rin_accessibility_service_client_publish(
    RinAccessibilityServiceClientV1* client,
    const RinAccessibilityWireSnapshotV1* snapshot);
RinResultCode rin_accessibility_service_client_query(
    RinAccessibilityServiceClientV1* client,
    const RinAccessibilityServiceQueryV1* query,
    RinAccessibilityWireSnapshotV1* snapshot_out);
RinResultCode rin_accessibility_service_client_revoke(
    RinAccessibilityServiceClientV1* client);
RinResultCode rin_accessibility_service_client_request_action(
    RinAccessibilityServiceClientV1* client,
    const RinAccessibilityServiceActionV2* action);
/* Returns RIN_RESULT_TIMED_OUT when no server-initiated action is ready. */
RinResultCode rin_accessibility_service_client_receive_action(
    RinAccessibilityServiceClientV1* client, uint32_t timeout_ms,
    RinAccessibilityServiceActionV2* action_out);
RinResultCode rin_accessibility_service_client_complete_action(
    RinAccessibilityServiceClientV1* client, RinResultCode action_status);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_ACCESSIBILITY_SERVICE_CLIENT_H */


