/* SPDX-License-Identifier: MIT */
/* Public, bounded archive admission policy shared by FileManager and tools. */

#ifndef RINRUNTIME_ARCHIVE_POLICY_H
#define RINRUNTIME_ARCHIVE_POLICY_H

#include <stddef.h>
#include <stdint.h>

#include "unicode.h"

#define RINRUNTIME_ARCHIVE_ENTRY_LIMIT 4096u
#define RINRUNTIME_ARCHIVE_DEPTH_LIMIT 32u
#define RINRUNTIME_ARCHIVE_CONTENT_LIMIT UINT64_C(268435456)
#define RINRUNTIME_ARCHIVE_MAX_COMPRESSION_RATIO UINT64_C(1024)
#define RINRUNTIME_ARCHIVE_PATH_LIMIT 4096u
#define RINRUNTIME_ARCHIVE_COMPONENT_LIMIT 255u

static inline int rinruntime_archive_utf8_valid(const char* value,
                                                size_t value_size)
{
    size_t offset = 0u;
    if (value == NULL || value_size == 0u) return 0;
    while (offset < value_size) {
        uint32_t codepoint = 0u;
        size_t consumed = 0u;
        if (!rinruntime_utf8_decode(value, value_size, offset,
                                    &codepoint, &consumed) ||
            consumed == 0u || codepoint == 0u || codepoint < 0x20u ||
            codepoint == 0x7fu) return 0;
        offset += consumed;
    }
    return 1;
}

static inline int rinruntime_archive_component_valid(const char* name,
                                                     size_t name_size)
{
    size_t index;
    if (name == NULL || name_size == 0u ||
        name_size > RINRUNTIME_ARCHIVE_COMPONENT_LIMIT ||
        !rinruntime_archive_utf8_valid(name, name_size)) return 0;
    if ((name_size == 1u && name[0] == '.') ||
        (name_size == 2u && name[0] == '.' && name[1] == '.')) return 0;
    for (index = 0u; index < name_size; ++index)
        if (name[index] == '\0' || name[index] == '/' || name[index] == '\\')
            return 0;
    return 1;
}

static inline int rinruntime_archive_path_valid(const char* path,
                                                 size_t path_size,
                                                 int* out_directory,
                                                 size_t* out_depth)
{
    size_t content_size;
    size_t offset = 0u;
    size_t depth = 0u;
    int directory;
    if (path == NULL || path_size == 0u ||
        path_size > RINRUNTIME_ARCHIVE_PATH_LIMIT || path[0] == '/' ||
        !rinruntime_archive_utf8_valid(path, path_size)) return 0;
    directory = path[path_size - 1u] == '/';
    content_size = directory ? path_size - 1u : path_size;
    if (content_size == 0u) return 0;
    while (offset < content_size) {
        size_t end = offset;
        while (end < content_size && path[end] != '/') ++end;
        if (!rinruntime_archive_component_valid(path + offset, end - offset) ||
            ++depth > RINRUNTIME_ARCHIVE_DEPTH_LIMIT) return 0;
        if (end == content_size) break;
        offset = end + 1u;
    }
    if (out_directory != NULL) *out_directory = directory;
    if (out_depth != NULL) *out_depth = depth;
    return 1;
}

static inline int rinruntime_archive_entry_count_valid(size_t count)
{
    return count > 0u && count <= RINRUNTIME_ARCHIVE_ENTRY_LIMIT;
}

static inline int rinruntime_archive_entry_slot_available(size_t count)
{
    return count < RINRUNTIME_ARCHIVE_ENTRY_LIMIT;
}

static inline int rinruntime_archive_content_add(uint64_t current,
                                                 uint64_t amount,
                                                 uint64_t* out_total)
{
    if (out_total == NULL || current > RINRUNTIME_ARCHIVE_CONTENT_LIMIT ||
        amount > RINRUNTIME_ARCHIVE_CONTENT_LIMIT - current) return 0;
    *out_total = current + amount;
    return 1;
}

static inline int rinruntime_archive_compression_ratio_valid(
    uint64_t compressed, uint64_t uncompressed)
{
    if (uncompressed == 0u) return compressed == 0u;
    if (compressed == 0u) return 0;
    if (compressed > UINT64_MAX / RINRUNTIME_ARCHIVE_MAX_COMPRESSION_RATIO)
        return 1;
    return uncompressed <= compressed * RINRUNTIME_ARCHIVE_MAX_COMPRESSION_RATIO;
}

static inline int rinruntime_archive_range_within(uint64_t offset,
                                                  uint64_t size,
                                                  uint64_t limit)
{
    return offset <= limit && size <= limit - offset;
}

static inline int rinruntime_archive_method_supported(uint16_t method)
{
    return method == 0u || method == 8u;
}

static inline int rinruntime_archive_flags_supported(uint16_t flags)
{
    return (flags & (uint16_t)~0x0808u) == 0u;
}

#endif /* RINRUNTIME_ARCHIVE_POLICY_H */
