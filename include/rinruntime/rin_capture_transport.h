/* SPDX-License-Identifier: MIT */
/* Shared capture transport callback contract for kernel and userland owners. */

#ifndef RIN_SHARED_CAPTURE_TRANSPORT_H
#define RIN_SHARED_CAPTURE_TRANSPORT_H

#include <stdint.h>

#include <rin/capture.h>
#include <rin/resource/capability.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RIN_CAPTURE_TRANSPORT_VERSION 1u

typedef int32_t (*RinCaptureTransportOpenFn)(
    void* context,
    const RinDeviceCapabilitySubjectV1* subject,
    uint32_t resource,
    uint64_t* transport_cookie_out,
    RinCaptureTransportProfileV1* profile_out);

/* Writes exactly one RinCaptureChunkV1 followed by its payload. */
typedef int32_t (*RinCaptureTransportReadFn)(
    void* context,
    uint64_t transport_cookie,
    void* buffer,
    uint32_t buffer_capacity,
    uint32_t* transferred_out);

typedef int32_t (*RinCaptureTransportReleaseFn)(
    void* context,
    uint64_t transport_cookie);

/* A session keeps one negotiated format. max_frame_size is exact for
 * uncompressed video and an upper bound for PCM and MJPEG frames. */
/* Registration snapshots this table. The owner of context keeps it valid for
 * the lifetime of every consumer that receives the registered transport. */
typedef struct RinCaptureTransportV1 {
    uint32_t struct_size;
    uint16_t version;
    uint16_t flags;
    void* context;
    RinCaptureTransportOpenFn open;
    RinCaptureTransportReadFn read_chunk;
    RinCaptureTransportReleaseFn release;
    uint64_t reserved[4];
} RinCaptureTransportV1;

#ifdef __cplusplus
}
#endif

#endif /* RIN_SHARED_CAPTURE_TRANSPORT_H */
