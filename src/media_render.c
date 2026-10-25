/* SPDX-License-Identifier: MIT */
/* Runtime-owned compositor lease wrapper for authenticated video decoding. */
#include <rinruntime/render.h>

RinResult rinruntime_video_decode_frame_v1(
    RinRuntimeGuiHandle handle, RinMediaObject object,
    RinVideoFrameInfoV1* frame_info) {
    return rinruntime_video_decode_frame_with_options_v1(
        handle, object, NULL, frame_info);
}

RinResult rinruntime_video_decode_frame_with_options_v1(
    RinRuntimeGuiHandle handle, RinMediaObject object,
    const RinVideoDecodeOptionsV1* options,
    RinVideoFrameInfoV1* frame_info) {
    RinRenderTarget target = {0};
    RinResult decode_result;
    int release_result;
    int acquire_result;
    if (frame_info == NULL) return RIN_ERROR_INVALID_ARGUMENT;
    acquire_result = wnd_acquire_render_target(handle, &target);
    if (acquire_result != RIN_SUCCESS) return (RinResult)acquire_result;

    decode_result = options != NULL
        ? rin_video_decode_frame_with_options_v1(
              object, &target, options, frame_info)
        : rin_video_decode_frame_v1(object, &target, frame_info);
    release_result = wnd_release_render_target(handle, &target);
    if (release_result != RIN_SUCCESS) return (RinResult)release_result;
    if (decode_result != RIN_SUCCESS) return decode_result;
    if (frame_info->payload_size_bytes == 0u) return RIN_SUCCESS;
    return (RinResult)wnd_present(handle);
}
