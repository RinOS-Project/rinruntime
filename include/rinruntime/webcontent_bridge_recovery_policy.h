/* SPDX-License-Identifier: MIT */

#ifndef RIN_WEBCONTENT_BRIDGE_RECOVERY_POLICY_H
#define RIN_WEBCONTENT_BRIDGE_RECOVERY_POLICY_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RIN_WEBCONTENT_BRIDGE_POLICY_VERSION 2u

typedef enum RinWebContentBridgeLoadPhaseV1 {
    RIN_WEBCONTENT_BRIDGE_LOAD_PHASE_PAINT = 5,
    RIN_WEBCONTENT_BRIDGE_LOAD_PHASE_COMPLETE = 6
} RinWebContentBridgeLoadPhaseV1;

typedef struct RinWebContentBridgeLaunchPolicyV1 {
    uint32_t size;
    uint32_t version;
    uint8_t skip_implicit_headless_bootstrap_view;
    /* Zero selects the per-user durable CookieJar / StorageJar database. */
    uint8_t disable_sql_database;
    uint8_t disable_spare_webcontent_processes;
    uint8_t allow_popups;
    /* Zero selects the per-user durable HTTP cache. */
    uint8_t disable_http_disk_cache;
    uint8_t force_cpu_painting;
    uint8_t force_fontconfig;
    uint8_t disable_viewport_scrollbars;
    /* Cross-site navigation must use a fresh WebContent helper. */
    uint8_t enable_site_isolation;
    uint8_t reserved[7];
} RinWebContentBridgeLaunchPolicyV1;

typedef struct RinWebContentBridgeLoadFinishPlanV1 {
    uint32_t size;
    uint32_t version;
    uint8_t loading;
    uint8_t progress_floor;
    uint8_t clear_pending_url;
    uint8_t waiting_for_first_paint;
    uint8_t kick_first_frame;
    uint8_t load_phase;
    uint8_t reserved[2];
} RinWebContentBridgeLoadFinishPlanV1;

typedef struct RinWebContentBridgeFirstPaintPlanV1 {
    uint32_t size;
    uint32_t version;
    uint8_t complete_load;
    uint8_t clear_pending_url;
    uint8_t progress_value;
    uint8_t reserved[5];
} RinWebContentBridgeFirstPaintPlanV1;

typedef struct RinWebContentBridgeCrashPlanV1 {
    uint32_t size;
    uint32_t version;
    uint8_t copy_committed_to_pending;
    uint8_t clear_first_paint_wait;
    uint8_t reserved[6];
} RinWebContentBridgeCrashPlanV1;

/*
 * A successful capabilities reply, including a zero-capability reply, is a
 * stable statement for the lifetime of one Browser runtime.  A failed probe
 * is not: WebContent may still be under the service manager's restart
 * backoff, so leaving this cache unset makes the next optional-operation
 * attempt retry discovery.  The owner resets this state when its runtime
 * shuts down.
 */
typedef struct RinWebContentCapabilityCacheV1 {
    uint64_t capabilities;
    uint8_t has_valid_response;
    uint8_t reserved[7];
} RinWebContentCapabilityCacheV1;

static inline void rin_webcontent_capability_cache_reset(
    RinWebContentCapabilityCacheV1* cache)
{
    uint8_t* bytes;
    uint32_t index;
    if (cache == 0)
        return;
    bytes = (uint8_t*)cache;
    for (index = 0u; index < (uint32_t)sizeof(*cache); ++index)
        bytes[index] = 0u;
}

static inline int rin_webcontent_capability_cache_needs_query(
    const RinWebContentCapabilityCacheV1* cache)
{
    return cache != 0 && cache->has_valid_response == 0u;
}

/* Publish exactly one schema-validated service response per runtime. */
static inline int rin_webcontent_capability_cache_publish(
    RinWebContentCapabilityCacheV1* cache, uint64_t capabilities)
{
    if (cache == 0 || cache->has_valid_response != 0u)
        return 0;
    cache->capabilities = capabilities;
    cache->has_valid_response = 1u;
    return 1;
}

/* Invalid boolean inputs fail closed by suppressing implicit view creation. */
static inline int
rin_webcontent_should_create_implicit_headless_bootstrap_view(
    int headless_mode_present, int skip_implicit_view)
{
    if ((headless_mode_present != 0 && headless_mode_present != 1) ||
        (skip_implicit_view != 0 && skip_implicit_view != 1))
        return 0;
    return headless_mode_present != 0 && skip_implicit_view == 0;
}

int rin_webcontent_bridge_launch_policy_v1(
    RinWebContentBridgeLaunchPolicyV1* policy_out);

int rin_webcontent_bridge_load_finish_plan_v1(
    int has_first_paint_for_active_navigation,
    RinWebContentBridgeLoadFinishPlanV1* plan_out);

int rin_webcontent_bridge_first_paint_plan_v1(
    int first_paint_for_active_navigation,
    int waiting_for_first_paint_after_load_finish,
    RinWebContentBridgeFirstPaintPlanV1* plan_out);

int rin_webcontent_bridge_crash_plan_v1(
    int pending_url_empty, int committed_url_empty,
    RinWebContentBridgeCrashPlanV1* plan_out);

#ifdef __cplusplus
}
#endif

#endif /* RIN_WEBCONTENT_BRIDGE_RECOVERY_POLICY_H */
