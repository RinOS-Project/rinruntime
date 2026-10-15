/* SPDX-License-Identifier: MIT */
/* Main-document network failure admission for the WebContent bridge. */

#ifndef RIN_SHARED_WEBCONTENT_NETWORK_FAILURE_POLICY_H
#define RIN_SHARED_WEBCONTENT_NETWORK_FAILURE_POLICY_H

#include <stdint.h>

/* A renderer can issue requests for subresources while a document navigation
 * is active.  Only the one request selected for the current main-document
 * navigation may transition the Browser-facing page state to recovery. */
static inline int rin_webcontent_network_request_tracks_navigation(
    uint64_t request_id, uint64_t active_navigation_request_id,
    int navigation_loading, int request_is_top_level_pending_document)
{
    return request_id != 0u && request_id != UINT64_MAX &&
           active_navigation_request_id == 0u &&
           navigation_loading != 0 &&
           request_is_top_level_pending_document != 0;
}

/* A request completion is terminal only when it is the captured navigation
 * request, the navigation is still live, and RequestServer explicitly
 * supplied a network error.  Successful completions and stale/subresource
 * completions must not replace the current page with recovery UI. */
static inline int rin_webcontent_network_failure_ends_navigation(
    uint64_t request_id, uint64_t active_navigation_request_id,
    int navigation_loading, int has_network_error)
{
    return request_id != 0u && request_id != UINT64_MAX &&
           active_navigation_request_id != 0u &&
           active_navigation_request_id != UINT64_MAX &&
           request_id == active_navigation_request_id &&
           navigation_loading != 0 && has_network_error != 0;
}

#endif /* RIN_SHARED_WEBCONTENT_NETWORK_FAILURE_POLICY_H */
