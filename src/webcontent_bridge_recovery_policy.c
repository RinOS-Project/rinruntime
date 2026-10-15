/* SPDX-License-Identifier: MIT */

#include <rinruntime/webcontent_bridge_recovery_policy.h>

#include <stddef.h>

static void policy_zero(void* output, size_t size)
{
    size_t index;
    uint8_t* bytes = (uint8_t*)output;
    if (!output)
        return;
    for (index = 0; index < size; ++index)
        bytes[index] = 0u;
}

static int policy_boolean_valid(int value)
{
    return value == 0 || value == 1;
}

int rin_webcontent_bridge_launch_policy_v1(
    RinWebContentBridgeLaunchPolicyV1* policy_out)
{
    if (!policy_out)
        return 0;
    policy_zero(policy_out, sizeof(*policy_out));
    policy_out->size = (uint32_t)sizeof(*policy_out);
    policy_out->version = RIN_WEBCONTENT_BRIDGE_POLICY_VERSION;
    policy_out->skip_implicit_headless_bootstrap_view = 1u;
    /*
     * Browser sessions are product data, not disposable bridge state.
     * LibWebView creates the per-user Ladybird database before exposing the
     * first view, and CookieJar / StorageJar use it for durable cookies and
     * local storage.  Do not silently substitute the transient jars here.
     */
    policy_out->disable_sql_database = 0u;
    policy_out->disable_spare_webcontent_processes = 1u;
    policy_out->allow_popups = 1u;
    /* The HTTP cache is disposable bridge state.  It must not be opened
     * during the service wave: ISO-only boots have no writable RinFS mount,
     * so Ladybird's XDG cache mkdir would fail before the first page exists.
     * Durable cookies/storage remain enabled through the SQL database above
     * and are used whenever a writable RinFS is present. */
    policy_out->disable_http_disk_cache = 1u;
    policy_out->force_cpu_painting = 1u;
    policy_out->force_fontconfig = 1u;
    policy_out->disable_viewport_scrollbars = 1u;
    policy_out->enable_site_isolation = 1u;
    return 1;
}

int rin_webcontent_bridge_load_finish_plan_v1(
    int has_first_paint_for_active_navigation,
    RinWebContentBridgeLoadFinishPlanV1* plan_out)
{
    if (!plan_out)
        return 0;
    policy_zero(plan_out, sizeof(*plan_out));
    if (!policy_boolean_valid(has_first_paint_for_active_navigation))
        return 0;

    plan_out->size = (uint32_t)sizeof(*plan_out);
    plan_out->version = RIN_WEBCONTENT_BRIDGE_POLICY_VERSION;
    if (has_first_paint_for_active_navigation != 0) {
        plan_out->progress_floor = 100u;
        plan_out->clear_pending_url = 1u;
        plan_out->load_phase = RIN_WEBCONTENT_BRIDGE_LOAD_PHASE_COMPLETE;
    } else {
        plan_out->loading = 1u;
        plan_out->progress_floor = 95u;
        plan_out->waiting_for_first_paint = 1u;
        plan_out->kick_first_frame = 1u;
        plan_out->load_phase = RIN_WEBCONTENT_BRIDGE_LOAD_PHASE_PAINT;
    }
    return 1;
}

int rin_webcontent_bridge_first_paint_plan_v1(
    int first_paint_for_active_navigation,
    int waiting_for_first_paint_after_load_finish,
    RinWebContentBridgeFirstPaintPlanV1* plan_out)
{
    if (!plan_out)
        return 0;
    policy_zero(plan_out, sizeof(*plan_out));
    if (!policy_boolean_valid(first_paint_for_active_navigation) ||
        !policy_boolean_valid(waiting_for_first_paint_after_load_finish))
        return 0;

    plan_out->size = (uint32_t)sizeof(*plan_out);
    plan_out->version = RIN_WEBCONTENT_BRIDGE_POLICY_VERSION;
    if (first_paint_for_active_navigation != 0 &&
        waiting_for_first_paint_after_load_finish != 0) {
        plan_out->complete_load = 1u;
        plan_out->clear_pending_url = 1u;
        plan_out->progress_value = 100u;
    }
    return 1;
}

int rin_webcontent_bridge_crash_plan_v1(
    int pending_url_empty, int committed_url_empty,
    RinWebContentBridgeCrashPlanV1* plan_out)
{
    if (!plan_out)
        return 0;
    policy_zero(plan_out, sizeof(*plan_out));
    if (!policy_boolean_valid(pending_url_empty) ||
        !policy_boolean_valid(committed_url_empty))
        return 0;

    plan_out->size = (uint32_t)sizeof(*plan_out);
    plan_out->version = RIN_WEBCONTENT_BRIDGE_POLICY_VERSION;
    plan_out->copy_committed_to_pending =
        pending_url_empty != 0 && committed_url_empty == 0;
    plan_out->clear_first_paint_wait = 1u;
    return 1;
}
