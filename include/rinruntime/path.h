/* SPDX-License-Identifier: MIT */
#ifndef RINPATH_PATH_H
#define RINPATH_PATH_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RIN_PATH_INPUT_MAX 4096u
#define RIN_PATH_COMPONENT_MAX 255u

typedef enum RinPathResult {
    RIN_PATH_OK = 0,
    RIN_PATH_INVALID_ARGUMENT = -1,
    RIN_PATH_BUFFER_TOO_SMALL = -2,
    RIN_PATH_INVALID = -3,
    RIN_PATH_TRAVERSAL = -4
} RinPathResult;

/* Sizes exclude the terminating NUL. output_capacity includes it. */
RinPathResult rin_path_basename(const char* input, size_t input_size,
                                char* output, size_t output_capacity,
                                size_t* required);
RinPathResult rin_path_dirname(const char* input, size_t input_size,
                               char* output, size_t output_capacity,
                               size_t* required);
RinPathResult rin_path_extension(const char* input, size_t input_size,
                                 char* output, size_t output_capacity,
                                 size_t* required);
RinPathResult rin_path_join(const char* left, size_t left_size,
                            const char* right, size_t right_size,
                            char* output, size_t output_capacity,
                            size_t* required);
RinPathResult rin_path_normalize(const char* input, size_t input_size,
                                 char* output, size_t output_capacity,
                                 size_t* required);
RinPathResult rin_path_remove_dot_segments(const char* input, size_t input_size,
                                           char* output, size_t output_capacity,
                                           size_t* required);
RinPathResult rin_path_relative(const char* base, size_t base_size,
                                const char* target, size_t target_size,
                                char* output, size_t output_capacity,
                                size_t* required);
RinPathResult rin_path_normalize_separators(const char* input, size_t input_size,
                                            char* output, size_t output_capacity,
                                            size_t* required);

/* These predicates do not normalize or authorize a path. */
int rin_path_has_traversal(const char* input, size_t input_size);
int rin_path_filename_valid(const char* input, size_t input_size);
int rin_path_absolute_canonical_valid(const char* input, size_t input_size);

#ifdef __cplusplus
}
#endif

#endif /* RINPATH_PATH_H */


