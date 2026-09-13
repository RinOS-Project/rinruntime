/* SPDX-License-Identifier: MIT */

#include <rinruntime/path.h>

#include <rinruntime/unicode.h>

#include <string.h>

static int path_separator(char value)
{
    return value == '/' || value == '\\';
}

static int path_control_free(const char* input, size_t size)
{
    size_t valid_prefix = 0u;
    size_t index;
    if (input == NULL || size == 0u || size > RIN_PATH_INPUT_MAX ||
        !rinruntime_utf8_validate(input, size, &valid_prefix))
        return 0;
    for (index = 0u; index < size; ++index) {
        unsigned char value = (unsigned char)input[index];
        if (value == 0u || value < 0x20u || value == 0x7fu) return 0;
    }
    return 1;
}

static RinPathResult path_copy_result(const char* input, size_t size,
                                      char* output, size_t capacity,
                                      size_t* required)
{
    if (required != NULL) *required = size;
    if (output == NULL && capacity != 0u) return RIN_PATH_INVALID_ARGUMENT;
    if (output == NULL || capacity <= size) return RIN_PATH_BUFFER_TOO_SMALL;
    if (size != 0u) memcpy(output, input, size);
    output[size] = '\0';
    return RIN_PATH_OK;
}

static RinPathResult path_emit(char* output, size_t capacity, size_t* length,
                               char value)
{
    if (output != NULL && *length + 1u < capacity) output[*length] = value;
    ++*length;
    return output == NULL || *length < capacity ? RIN_PATH_OK
                                                 : RIN_PATH_BUFFER_TOO_SMALL;
}

static void path_finish(char* output, size_t length)
{
    if (output != NULL) output[length] = '\0';
}

static RinPathResult path_normalize_pass(const char* input, size_t input_size,
                                         char* output, size_t output_capacity,
                                         size_t* length_out)
{
    size_t starts[RIN_PATH_INPUT_MAX / 2u + 1u];
    unsigned char dotdots[RIN_PATH_INPUT_MAX / 2u + 1u];
    size_t depth = 0u;
    size_t index = 0u;
    size_t length = 0u;
    int absolute;
    RinPathResult result = RIN_PATH_OK;

    absolute = path_separator(input[0]);
    if (absolute) {
        result = path_emit(output, output_capacity, &length, '/');
        index = 1u;
    }
    while (index < input_size) {
        size_t start;
        size_t end;
        size_t component_size;
        while (index < input_size && path_separator(input[index])) ++index;
        if (index == input_size) break;
        start = index;
        while (index < input_size && !path_separator(input[index])) ++index;
        end = index;
        component_size = end - start;
        if (component_size == 1u && input[start] == '.') continue;
        if (component_size == 2u && input[start] == '.' && input[start + 1u] == '.') {
            if (depth != 0u && dotdots[depth - 1u] == 0u) {
                length = starts[--depth];
                if (length > (absolute ? 1u : 0u)) --length;
                if (absolute && length == 1u) return RIN_PATH_TRAVERSAL;
                continue;
            }
            if (absolute) return RIN_PATH_TRAVERSAL;
        }
        if (depth >= sizeof(starts) / sizeof(starts[0])) return RIN_PATH_INVALID;
        if (length > (absolute ? 1u : 0u)) {
            result = path_emit(output, output_capacity, &length, '/');
        }
        starts[depth++] = length;
        dotdots[depth - 1u] = (unsigned char)(component_size == 2u &&
                                              input[start] == '.' &&
                                              input[start + 1u] == '.');
        while (start < end) {
            result = path_emit(output, output_capacity, &length,
                               input[start] == '\\' ? '/' : input[start]);
            ++start;
        }
    }
    if (length == 0u) result = path_emit(output, output_capacity, &length, '.');
    path_finish(output, length);
    if (length_out != NULL) *length_out = length;
    return result == RIN_PATH_OK ? RIN_PATH_OK : RIN_PATH_BUFFER_TOO_SMALL;
}

RinPathResult rin_path_normalize(const char* input, size_t input_size,
                                 char* output, size_t output_capacity,
                                 size_t* required)
{
    size_t length = 0u;
    RinPathResult result;
    if (!path_control_free(input, input_size) ||
        (output == NULL && output_capacity != 0u))
        return RIN_PATH_INVALID_ARGUMENT;
    result = path_normalize_pass(input, input_size, NULL, 0u, &length);
    if (result != RIN_PATH_OK) return result;
    if (required != NULL) *required = length;
    if (output == NULL || output_capacity <= length) return RIN_PATH_BUFFER_TOO_SMALL;
    result = path_normalize_pass(input, input_size, output, output_capacity, &length);
    if (result != RIN_PATH_OK) return RIN_PATH_BUFFER_TOO_SMALL;
    return RIN_PATH_OK;
}

RinPathResult rin_path_remove_dot_segments(const char* input, size_t input_size,
                                           char* output, size_t output_capacity,
                                           size_t* required)
{
    return rin_path_normalize(input, input_size, output, output_capacity, required);
}

RinPathResult rin_path_normalize_separators(const char* input, size_t input_size,
                                            char* output, size_t output_capacity,
                                            size_t* required)
{
    size_t index;
    if (!path_control_free(input, input_size)) return RIN_PATH_INVALID_ARGUMENT;
    if (required != NULL) *required = input_size;
    if (output == NULL || output_capacity <= input_size)
        return RIN_PATH_BUFFER_TOO_SMALL;
    for (index = 0u; index < input_size; ++index)
        output[index] = input[index] == '\\' ? '/' : input[index];
    output[input_size] = '\0';
    return RIN_PATH_OK;
}

RinPathResult rin_path_basename(const char* input, size_t input_size,
                                char* output, size_t output_capacity,
                                size_t* required)
{
    size_t end = input_size;
    size_t start;
    if (!path_control_free(input, input_size)) return RIN_PATH_INVALID_ARGUMENT;
    while (end != 0u && path_separator(input[end - 1u])) --end;
    if (end == 0u) return path_copy_result("/", 1u, output, output_capacity, required);
    start = end;
    while (start != 0u && !path_separator(input[start - 1u])) --start;
    return path_copy_result(input + start, end - start, output, output_capacity, required);
}

RinPathResult rin_path_dirname(const char* input, size_t input_size,
                               char* output, size_t output_capacity,
                               size_t* required)
{
    size_t end = input_size;
    size_t slash;
    if (!path_control_free(input, input_size)) return RIN_PATH_INVALID_ARGUMENT;
    while (end != 0u && path_separator(input[end - 1u])) --end;
    if (end == 0u) return path_copy_result("/", 1u, output, output_capacity, required);
    slash = end;
    while (slash != 0u && !path_separator(input[slash - 1u])) --slash;
    if (slash == 0u) return path_copy_result(".", 1u, output, output_capacity, required);
    while (slash > 1u && path_separator(input[slash - 1u])) --slash;
    return path_copy_result(input, slash,
                            output, output_capacity, required);
}

RinPathResult rin_path_extension(const char* input, size_t input_size,
                                 char* output, size_t output_capacity,
                                 size_t* required)
{
    size_t end = input_size;
    size_t file_end;
    size_t index;
    size_t start;
    size_t dot = input_size;
    if (!path_control_free(input, input_size)) return RIN_PATH_INVALID_ARGUMENT;
    while (end != 0u && path_separator(input[end - 1u])) --end;
    file_end = end;
    start = end;
    while (start != 0u && !path_separator(input[start - 1u])) --start;
    index = end;
    while (index > start) {
        --index;
        if (input[index] == '.') {
            dot = index;
            break;
        }
    }
    if (dot == input_size || dot == start || dot + 1u == file_end)
        return path_copy_result("", 0u, output, output_capacity, required);
    return path_copy_result(input + dot + 1u, file_end - dot - 1u,
                            output, output_capacity, required);
}

RinPathResult rin_path_join(const char* left, size_t left_size,
                            const char* right, size_t right_size,
                            char* output, size_t output_capacity,
                            size_t* required)
{
    size_t raw_size;
    RinPathResult result;
    if (!path_control_free(left, left_size) ||
        !path_control_free(right, right_size) || path_separator(right[0]))
        return RIN_PATH_INVALID_ARGUMENT;
    if (left_size > RIN_PATH_INPUT_MAX - right_size - 1u)
        return RIN_PATH_INVALID_ARGUMENT;
    raw_size = left_size + right_size + (left_size != 0u ? 1u : 0u);
    if (raw_size > RIN_PATH_INPUT_MAX) return RIN_PATH_INVALID_ARGUMENT;
    {
        char joined[RIN_PATH_INPUT_MAX + 1u];
        memcpy(joined, left, left_size);
        if (left_size != 0u) joined[left_size] = '/';
        memcpy(joined + left_size + (left_size != 0u ? 1u : 0u), right, right_size);
        result = rin_path_normalize(joined, raw_size, output, output_capacity, required);
    }
    return result;
}

static int path_component_equal(const char* left, size_t left_size,
                                const char* right, size_t right_size)
{
    return left_size == right_size && memcmp(left, right, left_size) == 0;
}

RinPathResult rin_path_relative(const char* base, size_t base_size,
                                const char* target, size_t target_size,
                                char* output, size_t output_capacity,
                                size_t* required)
{
    char base_normalized[RIN_PATH_INPUT_MAX + 1u];
    char target_normalized[RIN_PATH_INPUT_MAX + 1u];
    size_t base_length = 0u;
    size_t target_length = 0u;
    size_t base_index = 0u;
    size_t target_index = 0u;
    size_t common = 0u;
    size_t length = 0u;
    int base_absolute;
    int target_absolute;
    RinPathResult result;
    if (rin_path_normalize(base, base_size, base_normalized,
                           sizeof(base_normalized), &base_length) != RIN_PATH_OK ||
        rin_path_normalize(target, target_size, target_normalized,
                           sizeof(target_normalized), &target_length) != RIN_PATH_OK)
        return RIN_PATH_INVALID_ARGUMENT;
    if (base_length == 1u && base_normalized[0] == '.') base_length = 0u;
    if (target_length == 1u && target_normalized[0] == '.') target_length = 0u;
    base_absolute = base_normalized[0] == '/';
    target_absolute = target_normalized[0] == '/';
    if (base_absolute != target_absolute) return RIN_PATH_INVALID_ARGUMENT;
    base_index = base_absolute ? 1u : 0u;
    target_index = target_absolute ? 1u : 0u;
    while (base_index < base_length && target_index < target_length) {
        size_t base_end = base_index;
        size_t target_end = target_index;
        while (base_end < base_length && base_normalized[base_end] != '/') ++base_end;
        while (target_end < target_length && target_normalized[target_end] != '/') ++target_end;
        if (!path_component_equal(base_normalized + base_index, base_end - base_index,
                                  target_normalized + target_index, target_end - target_index))
            break;
        ++common;
        base_index = base_end == base_length ? base_end : base_end + 1u;
        target_index = target_end == target_length ? target_end : target_end + 1u;
    }
    base_index = base_absolute ? 1u : 0u;
    while (common != 0u) {
        size_t end = base_index;
        while (end < base_length && base_normalized[end] != '/') ++end;
        base_index = end == base_length ? end : end + 1u;
        --common;
    }
    while (base_index < base_length) {
        size_t end = base_index;
        while (end < base_length && base_normalized[end] != '/') ++end;
        result = path_emit(output, output_capacity, &length, '.');
        if (result == RIN_PATH_OK) result = path_emit(output, output_capacity, &length, '.');
        if (end < base_length) result = path_emit(output, output_capacity, &length, '/');
        base_index = end == base_length ? end : end + 1u;
    }
    target_index = target_absolute ? 1u : 0u;
    /* Recompute the common prefix boundary without retaining dynamic state. */
    {
        size_t left_index = base_absolute ? 1u : 0u;
        size_t right_index = target_absolute ? 1u : 0u;
        while (left_index < base_length && right_index < target_length) {
            size_t left_end = left_index;
            size_t right_end = right_index;
            while (left_end < base_length && base_normalized[left_end] != '/') ++left_end;
            while (right_end < target_length && target_normalized[right_end] != '/') ++right_end;
            if (!path_component_equal(base_normalized + left_index, left_end - left_index,
                                      target_normalized + right_index, right_end - right_index))
                break;
            if (left_end == base_length || right_end == target_length) {
                left_index = left_end;
                right_index = right_end;
                break;
            }
            left_index = left_end + 1u;
            right_index = right_end + 1u;
        }
        base_index = left_index;
        target_index = right_index;
    }
    if (length != 0u && target_index < target_length)
        result = path_emit(output, output_capacity, &length, '/');
    while (target_index < target_length) {
        size_t end = target_index;
        while (end < target_length && target_normalized[end] != '/') ++end;
        while (target_index < end) {
            result = path_emit(output, output_capacity, &length, target_normalized[target_index++]);
        }
        if (end < target_length) {
            target_index = end + 1u;
            if (target_index < target_length)
                result = path_emit(output, output_capacity, &length, '/');
        }
    }
    if (length == 0u) result = path_emit(output, output_capacity, &length, '.');
    path_finish(output, length);
    if (required != NULL) *required = length;
    return output == NULL || output_capacity > length ? RIN_PATH_OK : RIN_PATH_BUFFER_TOO_SMALL;
}

int rin_path_has_traversal(const char* input, size_t input_size)
{
    size_t index = 0u;
    if (!path_control_free(input, input_size)) return 1;
    while (index < input_size) {
        size_t start;
        size_t end;
        while (index < input_size && path_separator(input[index])) ++index;
        start = index;
        while (index < input_size && !path_separator(input[index])) ++index;
        end = index;
        if (end - start == 2u && input[start] == '.' && input[start + 1u] == '.') return 1;
    }
    return 0;
}

int rin_path_filename_valid(const char* input, size_t input_size)
{
    size_t index;
    if (!path_control_free(input, input_size) || input_size == 0u ||
        input_size > RIN_PATH_COMPONENT_MAX ||
        (input_size == 1u && input[0] == '.') ||
        (input_size == 2u && input[0] == '.' && input[1] == '.') ||
        input[0] == ' ' || input[input_size - 1u] == ' ' ||
        input[input_size - 1u] == '.' ) return 0;
    for (index = 0u; index < input_size; ++index)
        if (path_separator(input[index]) || input[index] == ':') return 0;
    return 1;
}

int rin_path_absolute_canonical_valid(const char* input, size_t input_size)
{
    char normalized[RIN_PATH_INPUT_MAX + 1u];
    size_t normalized_size = 0u;
    if (!path_control_free(input, input_size) || input[0] != '/' ||
        rin_path_has_traversal(input, input_size) ||
        rin_path_normalize(input, input_size, normalized, sizeof(normalized),
                           &normalized_size) != RIN_PATH_OK)
        return 0;
    return normalized_size == input_size && memcmp(normalized, input, input_size) == 0;
}

