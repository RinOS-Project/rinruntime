/* SPDX-License-Identifier: MIT */
/* Runtime-owned compositor lease wrapper for authenticated video decoding. */
#include <string.h>

#include <rinruntime/render.h>

static int runtime_video_frame_info_valid(
    const RinVideoFrameInfoV1* frame_info) {
    return frame_info != NULL &&
           frame_info->struct_size == sizeof(*frame_info) &&
           frame_info->version == RIN_SDK_STRUCT_VERSION_1;
}

static void runtime_video_frame_info_reset(RinVideoFrameInfoV1* frame_info) {
    memset(frame_info, 0, sizeof(*frame_info));
    frame_info->struct_size = sizeof(*frame_info);
    frame_info->version = RIN_SDK_STRUCT_VERSION_1;
}

static int runtime_video_decode_options_valid(
    const RinVideoDecodeOptionsV1* options) {
    return options == NULL ||
           (options->struct_size == sizeof(*options) &&
            options->version == RIN_SDK_STRUCT_VERSION_1 &&
            options->reserved[0] == 0u && options->reserved[1] == 0u);
}

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
    if (!runtime_video_frame_info_valid(frame_info))
        return RIN_ERROR_ABI_MISMATCH;
    runtime_video_frame_info_reset(frame_info);
    if (!runtime_video_decode_options_valid(options))
        return RIN_ERROR_ABI_MISMATCH;

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
