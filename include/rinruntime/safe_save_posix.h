/* SPDX-License-Identifier: MIT */
/* POSIX/RinOS backend for the public safe-save contract. */

#ifndef RINRUNTIME_SAFE_SAVE_POSIX_H
#define RINRUNTIME_SAFE_SAVE_POSIX_H

#include "safe_save.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Replaces an absolute canonical target through an exclusive private file in
 * the same directory.  It is suitable for external applications which use
 * the standard RinOS/POSIX descriptor and rename semantics. */
RinRuntimeSafeSaveResult rinruntime_safe_save_posix(
    const char* target_path, const uint8_t* data, uint32_t size);

#ifdef __cplusplus
}
#endif

#endif /* RINRUNTIME_SAFE_SAVE_POSIX_H */


