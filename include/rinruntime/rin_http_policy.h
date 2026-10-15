/* SPDX-License-Identifier: MIT */
#ifndef RIN_SHARED_HTTP_POLICY_H
#define RIN_SHARED_HTTP_POLICY_H

#include <stdint.h>

#define RIN_HTTP_STABLE_ORIGIN_LIMIT UINT32_C(6)
#define RIN_HTTP_UNSTABLE_ORIGIN_LIMIT UINT32_C(1)

typedef enum RinHttpRetryWait {
    RIN_HTTP_RETRY_WAIT_NONE = 0,
    RIN_HTTP_RETRY_WAIT_DEFAULT = 1,
    RIN_HTTP_RETRY_WAIT_READ = 2,
    RIN_HTTP_RETRY_WAIT_WRITE = 3
} RinHttpRetryWait;

typedef struct RinHttpRetryCodes {
    int tls_want_read;
    int tls_want_write;
    int again;
    int would_block;
    int in_progress;
    int interrupted;
} RinHttpRetryCodes;

typedef struct RinHttpRetryDecision {
    int retryable;
    RinHttpRetryWait wait;
} RinHttpRetryDecision;

typedef enum RinHttpSubmitStage {
    RIN_HTTP_SUBMIT_INVALID = 0,
    RIN_HTTP_SUBMIT_HEADER = 1,
    RIN_HTTP_SUBMIT_PAYLOAD = 2,
    RIN_HTTP_SUBMIT_WAIT = 3
} RinHttpSubmitStage;

static inline RinHttpRetryDecision rin_http_retry_decide(
    int result, int saved_errno, const RinHttpRetryCodes* codes) {
    RinHttpRetryDecision decision = {0, RIN_HTTP_RETRY_WAIT_NONE};
    if (!codes) return decision;
    if (result == codes->tls_want_read) {
        decision.retryable = 1;
        decision.wait = RIN_HTTP_RETRY_WAIT_READ;
    } else if (result == codes->tls_want_write) {
        decision.retryable = 1;
        decision.wait = RIN_HTTP_RETRY_WAIT_WRITE;
    } else if (saved_errno == codes->again ||
               saved_errno == codes->would_block ||
               saved_errno == codes->in_progress) {
        decision.retryable = 1;
        decision.wait = RIN_HTTP_RETRY_WAIT_DEFAULT;
    } else if (saved_errno == codes->interrupted) {
        decision.retryable = 1;
    }
    return decision;
}

static inline uint16_t rin_http_retry_wait_events(
    RinHttpRetryDecision decision, uint16_t default_events,
    uint16_t read_event, uint16_t write_event) {
    if (!decision.retryable) return 0u;
    if (decision.wait == RIN_HTTP_RETRY_WAIT_READ) return read_event;
    if (decision.wait == RIN_HTTP_RETRY_WAIT_WRITE) return write_event;
    if (decision.wait == RIN_HTTP_RETRY_WAIT_DEFAULT) return default_events;
    return 0u;
}

static inline uint16_t rin_http_poll_events(uint16_t wait_events,
                                             uint16_t error_event,
                                             uint16_t hangup_event) {
    return (uint16_t)(wait_events | error_event | hangup_event);
}

static inline uint32_t rin_http_origin_limit(int unstable) {
    return unstable ? RIN_HTTP_UNSTABLE_ORIGIN_LIMIT : RIN_HTTP_STABLE_ORIGIN_LIMIT;
}

static inline int rin_http_origin_permit_available(int unstable, uint32_t inflight) {
    return inflight < rin_http_origin_limit(unstable);
}

static inline int rin_http_origin_release(uint32_t* inflight) {
    if (!inflight || *inflight == 0u) return 0;
    --*inflight;
    return 1;
}

static inline RinHttpSubmitStage rin_http_submit_after_header(
    uint64_t sent, uint64_t total, uint64_t payload_size) {
    if (total == 0u || sent > total) return RIN_HTTP_SUBMIT_INVALID;
    if (sent < total) return RIN_HTTP_SUBMIT_HEADER;
    return payload_size == 0u ? RIN_HTTP_SUBMIT_WAIT : RIN_HTTP_SUBMIT_PAYLOAD;
}

static inline RinHttpSubmitStage rin_http_submit_after_payload(
    uint64_t sent, uint64_t total) {
    if (total == 0u || sent > total) return RIN_HTTP_SUBMIT_INVALID;
    return sent < total ? RIN_HTTP_SUBMIT_PAYLOAD : RIN_HTTP_SUBMIT_WAIT;
}

static inline int rin_http_submit_completed(RinHttpSubmitStage stage) {
    return stage == RIN_HTTP_SUBMIT_WAIT;
}

/* Source-compatible aliases for the former Browser-local policy header. */
#define RIN_BROWSER_HTTP_STABLE_ORIGIN_LIMIT RIN_HTTP_STABLE_ORIGIN_LIMIT
#define RIN_BROWSER_HTTP_UNSTABLE_ORIGIN_LIMIT RIN_HTTP_UNSTABLE_ORIGIN_LIMIT
#define RinBrowserHttpRetryWait RinHttpRetryWait
#define RinBrowserHttpRetryCodes RinHttpRetryCodes
#define RinBrowserHttpRetryDecision RinHttpRetryDecision
#define RinBrowserHttpSubmitStage RinHttpSubmitStage
#define RIN_BROWSER_HTTP_RETRY_WAIT_NONE RIN_HTTP_RETRY_WAIT_NONE
#define RIN_BROWSER_HTTP_RETRY_WAIT_DEFAULT RIN_HTTP_RETRY_WAIT_DEFAULT
#define RIN_BROWSER_HTTP_RETRY_WAIT_READ RIN_HTTP_RETRY_WAIT_READ
#define RIN_BROWSER_HTTP_RETRY_WAIT_WRITE RIN_HTTP_RETRY_WAIT_WRITE
#define RIN_BROWSER_HTTP_SUBMIT_INVALID RIN_HTTP_SUBMIT_INVALID
#define RIN_BROWSER_HTTP_SUBMIT_HEADER RIN_HTTP_SUBMIT_HEADER
#define RIN_BROWSER_HTTP_SUBMIT_PAYLOAD RIN_HTTP_SUBMIT_PAYLOAD
#define RIN_BROWSER_HTTP_SUBMIT_WAIT RIN_HTTP_SUBMIT_WAIT
#define rin_browser_http_retry_decide rin_http_retry_decide
#define rin_browser_http_retry_wait_events rin_http_retry_wait_events
#define rin_browser_http_poll_events rin_http_poll_events
#define rin_browser_http_origin_limit rin_http_origin_limit
#define rin_browser_http_origin_permit_available rin_http_origin_permit_available
#define rin_browser_http_origin_release rin_http_origin_release
#define rin_browser_http_submit_after_header rin_http_submit_after_header
#define rin_browser_http_submit_after_payload rin_http_submit_after_payload
#define rin_browser_http_submit_completed rin_http_submit_completed

#endif
