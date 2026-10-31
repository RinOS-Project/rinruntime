/* SPDX-License-Identifier: MIT */
#ifndef RINRUNTIME_FILE_OPERATION_INTERNAL_H
#define RINRUNTIME_FILE_OPERATION_INTERNAL_H

#include <stdint.h>

/* Validate a NUL-terminated absolute path inside a buffer of capacity bytes. */
int rinruntime_file_operation_path_valid_limit_internal(
    const char* path, uint32_t capacity);

#endif /* RINRUNTIME_FILE_OPERATION_INTERNAL_H */
