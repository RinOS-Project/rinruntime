/* SPDX-License-Identifier: MIT */
/* Public C render-target lifetime API. */
#ifndef RINRUNTIME_RENDER_H
#define RINRUNTIME_RENDER_H

#include "window.h"
#include <rin/media.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The returned target is borrowed until rinruntime_end_frame.  It must not be
 * cached, mapped again, or used from another thread. */
int rinruntime_begin_frame(RinRuntimeGuiHandle handle,
                           RinRenderTarget* target_out);
/* Releases the exact target acquired by begin_frame and presents it. */
int rinruntime_end_frame(RinRuntimeGuiHandle handle,
                         const RinRenderTarget* target);
/* Decode through the authenticated SDK VIDEO route into a target acquired
 * from this exact Runtime window. The target is always released before this
 * function returns; a nonempty successful frame is then submitted for
 * presentation. End-of-stream releases without presenting a new frame. */
RinResult rinruntime_video_decode_frame_v1(
    RinRuntimeGuiHandle handle, RinMediaObject object,
    RinVideoFrameInfoV1* frame_info);
RinResult rinruntime_video_decode_frame_with_options_v1(
    RinRuntimeGuiHandle handle, RinMediaObject object,
    const RinVideoDecodeOptionsV1* options,
    RinVideoFrameInfoV1* frame_info);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_RENDER_H */
