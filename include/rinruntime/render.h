/* SPDX-License-Identifier: MIT */
/* Public C render-target lifetime API. */
#ifndef RINRUNTIME_RENDER_H
#define RINRUNTIME_RENDER_H

#include "window.h"

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

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_RENDER_H */
