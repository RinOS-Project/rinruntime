/* SPDX-License-Identifier: MIT */
/* Authenticated, generation-bound producer adapter for WebContent permission events. */

#ifndef RIN_SHARED_WEBCONTENT_PERMISSION_PRODUCER_H
#define RIN_SHARED_WEBCONTENT_PERMISSION_PRODUCER_H

#include <stdint.h>
#include <string.h>

#include "webcontent_client_policy.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A page owns at most four outstanding mediation events.  A full queue is a
 * producer failure, not an eviction: the caller must tear down the page so a
 * renderer cannot continue with an incomplete permission view. */
#define RIN_WEBCONTENT_PERMISSION_PRODUCER_MAX_EVENTS UINT32_C(4)

typedef struct RinWebContentPermissionProducerV1 {
    uint32_t page_id;
    uint32_t navigation_generation;
    uint32_t event_count;
    uint32_t bound;
    uint64_t renderer_generation;
    uint64_t next_request_id;
    char authenticated_origin[RIN_WEBCONTENT_URL_MAX];
    RinWebContentPermissionEventV1 events[
        RIN_WEBCONTENT_PERMISSION_PRODUCER_MAX_EVENTS];
} RinWebContentPermissionProducerV1;

static inline int rin_webcontent_permission_origin_valid(const char* origin)
{
    size_t length = 0u;
    size_t scheme_size = 0u;
    size_t index;
    if (!rin_webcontent_client_url_valid(origin) || origin == NULL)
        return 0;
    if (strncmp(origin, "https://", 8u) == 0)
        scheme_size = 8u;
    else if (strncmp(origin, "http://", 7u) == 0)
        scheme_size = 7u;
    else
        return 0;
    (void)rin_webcontent_client_bounded_cstr_length(
        origin, RIN_WEBCONTENT_URL_MAX, 0, 1, &length);
    if (length <= scheme_size || origin[scheme_size] == '/' ||
        origin[scheme_size] == '?' || origin[scheme_size] == '#')
        return 0;
    /* Origin metadata may contain a path for compatibility with the Browser
     * gate, but never credentials, a second scheme separator, or controls. */
    for (index = scheme_size; index < length; ++index) {
        unsigned char byte = (unsigned char)origin[index];
        if (byte < 0x21u || byte == 0x7fu || byte == '\\' || byte == '@')
            return 0;
    }
    return 1;
}

static inline void rin_webcontent_permission_producer_initialize(
    RinWebContentPermissionProducerV1* producer)
{
    if (producer != NULL)
        memset(producer, 0, sizeof(*producer));
}

static inline int rin_webcontent_permission_producer_bind(
    RinWebContentPermissionProducerV1* producer, uint32_t page_id,
    uint32_t navigation_generation, uint64_t renderer_generation,
    const char* authenticated_origin)
{
    size_t origin_size = 0u;
    if (producer == NULL || page_id == 0u || navigation_generation == 0u ||
        renderer_generation == 0u || !rin_webcontent_permission_origin_valid(
            authenticated_origin) ||
        !rin_webcontent_client_bounded_cstr_length(
            authenticated_origin, RIN_WEBCONTENT_URL_MAX, 0, 1,
            &origin_size) || origin_size >= RIN_WEBCONTENT_URL_MAX)
        return 0;
    memset(producer, 0, sizeof(*producer));
    producer->page_id = page_id;
    producer->navigation_generation = navigation_generation;
    producer->renderer_generation = renderer_generation;
    producer->next_request_id = 1u;
    producer->bound = 1u;
    memcpy(producer->authenticated_origin, authenticated_origin,
           origin_size + 1u);
    return 1;
}

static inline void rin_webcontent_permission_producer_unbind(
    RinWebContentPermissionProducerV1* producer)
{
    if (producer != NULL)
        memset(producer, 0, sizeof(*producer));
}

static inline int rin_webcontent_permission_producer_request_with_origin(
    RinWebContentPermissionProducerV1* producer, uint32_t page_id,
    uint32_t navigation_generation, uint64_t renderer_generation,
    const char* authenticated_origin,
    const char* permission_type, const char* description,
    uint64_t* request_id_out)
{
    RinWebContentPermissionEventV1* event;
    size_t origin_size = 0u;
    if (request_id_out != NULL) *request_id_out = 0u;
    if (producer == NULL || producer->bound != 1u || page_id != producer->page_id ||
        navigation_generation != producer->navigation_generation ||
        renderer_generation == 0u ||
        renderer_generation != producer->renderer_generation ||
        authenticated_origin == NULL ||
        !rin_webcontent_permission_origin_valid(authenticated_origin) ||
        !rin_webcontent_client_permission_type_valid(permission_type) ||
        !rin_webcontent_client_permission_description_valid(description) ||
        producer->event_count >= RIN_WEBCONTENT_PERMISSION_PRODUCER_MAX_EVENTS ||
        producer->next_request_id == 0u || producer->next_request_id == UINT64_MAX ||
        !rin_webcontent_client_bounded_cstr_length(
            authenticated_origin, RIN_WEBCONTENT_URL_MAX, 0, 1,
            &origin_size))
        return 0;
    event = &producer->events[producer->event_count];
    memset(event, 0, sizeof(*event));
    event->struct_size = sizeof(*event);
    event->version = RIN_WEBCONTENT_PERMISSION_EXTENSION_ABI_VERSION;
    event->event = RIN_WEBCONTENT_PERMISSION_EVENT_REQUEST;
    event->navigation_generation = navigation_generation;
    event->request_id = producer->next_request_id++;
    memcpy(event->permission_type, permission_type, strlen(permission_type) + 1u);
    memcpy(event->origin, authenticated_origin, origin_size + 1u);
    memcpy(event->description, description, strlen(description) + 1u);
    if (!rin_webcontent_client_permission_event_valid(
            event, navigation_generation, event->request_id - 1u)) {
        memset(event, 0, sizeof(*event));
        return 0;
    }
    ++producer->event_count;
    if (request_id_out != NULL) *request_id_out = event->request_id;
    return 1;
}

static inline int rin_webcontent_permission_producer_request(
    RinWebContentPermissionProducerV1* producer, uint32_t page_id,
    uint32_t navigation_generation, uint64_t renderer_generation,
    const char* authenticated_origin,
    const char* permission_type, const char* description,
    uint64_t* request_id_out)
{
    if (producer == NULL || producer->bound != 1u ||
        authenticated_origin == NULL ||
        strcmp(authenticated_origin, producer->authenticated_origin) != 0)
        return 0;
    return rin_webcontent_permission_producer_request_with_origin(
        producer, page_id, navigation_generation, renderer_generation,
        authenticated_origin, permission_type, description, request_id_out);
}

/* The only caller is the trusted WebContent engine callback, which derives
 * this origin from the requesting Document after checking Permissions Policy.
 * Script never supplies this field directly. */
static inline int rin_webcontent_permission_producer_request_from_document(
    RinWebContentPermissionProducerV1* producer, uint32_t page_id,
    uint32_t navigation_generation, uint64_t renderer_generation,
    const char* document_origin, const char* permission_type,
    const char* description, uint64_t* request_id_out)
{
    return rin_webcontent_permission_producer_request_with_origin(
        producer, page_id, navigation_generation, renderer_generation,
        document_origin, permission_type, description, request_id_out);
}

/* Generate a request from renderer permission metadata without accepting an
 * origin from the renderer.  The origin copied into the event is the one
 * authenticated during bind(), so a renderer cannot redirect a prompt to a
 * different site by supplying a forged origin alongside its permission type. */
static inline int rin_webcontent_permission_producer_request_bound(
    RinWebContentPermissionProducerV1* producer, uint32_t page_id,
    uint32_t navigation_generation, uint64_t renderer_generation,
    const char* permission_type,
    const char* description, uint64_t* request_id_out)
{
    if (producer == NULL || producer->bound != 1u)
        return 0;
    return rin_webcontent_permission_producer_request(
        producer, page_id, navigation_generation, renderer_generation,
        producer->authenticated_origin, permission_type, description,
        request_id_out);
}

static inline int rin_webcontent_permission_producer_cancel(
    RinWebContentPermissionProducerV1* producer, uint32_t page_id,
    uint32_t navigation_generation, uint64_t renderer_generation,
    uint64_t request_id)
{
    uint32_t index;
    if (producer == NULL || producer->bound != 1u || page_id != producer->page_id ||
        navigation_generation != producer->navigation_generation ||
        renderer_generation == 0u ||
        renderer_generation != producer->renderer_generation ||
        request_id == 0u)
        return 0;
    for (index = 0u; index < producer->event_count; ++index) {
        RinWebContentPermissionEventV1* event = &producer->events[index];
        if (event->request_id != request_id) continue;
        if (event->event != RIN_WEBCONTENT_PERMISSION_EVENT_REQUEST ||
            !rin_webcontent_client_permission_event_valid(
                event, producer->navigation_generation, request_id - 1u))
            return 0;
        event->event = RIN_WEBCONTENT_PERMISSION_EVENT_CANCEL;
        memset(event->origin, 0, sizeof(event->origin));
        memset(event->description, 0, sizeof(event->description));
        return 1;
    }
    return 0;
}

static inline int rin_webcontent_permission_producer_poll(
    RinWebContentPermissionProducerV1* producer, uint32_t page_id,
    uint32_t navigation_generation, uint64_t renderer_generation,
    uint64_t after_request_id,
    RinWebContentPermissionEventV1* output)
{
    uint32_t index;
    if (output != NULL) memset(output, 0, sizeof(*output));
    if (producer == NULL || output == NULL || producer->bound != 1u ||
        page_id != producer->page_id ||
        navigation_generation != producer->navigation_generation ||
        renderer_generation == 0u ||
        renderer_generation != producer->renderer_generation)
        return 0;
    for (index = 0u; index < producer->event_count; ++index) {
        const RinWebContentPermissionEventV1* event = &producer->events[index];
        const int is_pending_request_cancellation =
            event->request_id == after_request_id &&
            event->event == RIN_WEBCONTENT_PERMISSION_EVENT_CANCEL;
        if (event->request_id < after_request_id ||
            (event->request_id == after_request_id &&
             !is_pending_request_cancellation))
            continue;
        *output = *event;
        if (!rin_webcontent_client_permission_event_valid(
                output, navigation_generation,
                is_pending_request_cancellation ? after_request_id - 1u
                                               : after_request_id)) {
            memset(output, 0, sizeof(*output));
            return 0;
        }
        return 1;
    }
    output->struct_size = sizeof(*output);
    output->version = RIN_WEBCONTENT_PERMISSION_EXTENSION_ABI_VERSION;
    output->navigation_generation = navigation_generation;
    return rin_webcontent_client_permission_event_valid(
        output, navigation_generation, after_request_id);
}

static inline int rin_webcontent_permission_producer_complete_internal(
    RinWebContentPermissionProducerV1* producer, uint32_t page_id,
    uint64_t renderer_generation,
    const RinWebContentPermissionCompleteV1* completion,
    const char* expected_permission_type)
{
    uint32_t index;
    if (producer == NULL || completion == NULL || producer->bound != 1u ||
        page_id != producer->page_id ||
        renderer_generation == 0u ||
        renderer_generation != producer->renderer_generation ||
        !rin_webcontent_client_permission_complete_valid(completion) ||
        completion->navigation_generation != producer->navigation_generation)
        return 0;
    for (index = 0u; index < producer->event_count; ++index) {
        if (producer->events[index].request_id != completion->request_id)
            continue;
        if (expected_permission_type != NULL &&
            (!rin_webcontent_client_permission_type_valid(
                 expected_permission_type) ||
             strcmp(producer->events[index].permission_type,
                    expected_permission_type) != 0))
            return 0;
        /* A cancellation is terminal.  Never let a stale Browser response
         * turn a renderer-issued CANCEL event back into an Allow/Block
         * decision after navigation, tab close, or revocation. */
        if (producer->events[index].event == RIN_WEBCONTENT_PERMISSION_EVENT_CANCEL &&
            completion->result != RIN_WEBCONTENT_PERMISSION_RESULT_CANCELLED)
            return 0;
        if (!rin_webcontent_client_permission_event_valid(
                &producer->events[index], producer->navigation_generation,
                completion->request_id - 1u))
            return 0;
        if (index + 1u < producer->event_count)
            memmove(&producer->events[index], &producer->events[index + 1u],
                    (producer->event_count - index - 1u) * sizeof(producer->events[0]));
        --producer->event_count;
        memset(&producer->events[producer->event_count], 0,
               sizeof(producer->events[producer->event_count]));
        return 1;
    }
    return 0;
}

static inline int rin_webcontent_permission_producer_complete(
    RinWebContentPermissionProducerV1* producer, uint32_t page_id,
    uint64_t renderer_generation,
    const RinWebContentPermissionCompleteV1* completion)
{
    return rin_webcontent_permission_producer_complete_internal(
        producer, page_id, renderer_generation, completion, NULL);
}

/* Complete only the permission family that owns the renderer callback.  A
 * service may support multiple permission event types, while a bridge such
 * as the notification adapter can safely dispatch only its own type. */
static inline int rin_webcontent_permission_producer_complete_type(
    RinWebContentPermissionProducerV1* producer, uint32_t page_id,
    uint64_t renderer_generation,
    const RinWebContentPermissionCompleteV1* completion,
    const char* expected_permission_type)
{
    return rin_webcontent_permission_producer_complete_internal(
        producer, page_id, renderer_generation, completion,
        expected_permission_type);
}

#ifdef __cplusplus
}
#endif

#endif
