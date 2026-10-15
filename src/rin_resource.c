/* SPDX-License-Identifier: MIT */
/* Strict, allocation-free RIN v3 resource and icon reader. */

#include <rinruntime/rin_resource.h>

#include <stdint.h>
#include <string.h>

#define RIN_RESOURCE_PNG_SIGNATURE_SIZE 8u

static int resource_add(size_t left, size_t right, size_t* result)
{
    if (!result || left > SIZE_MAX - right) return 0;
    *result = left + right;
    return 1;
}

static int resource_mul(size_t left, size_t right, size_t* result)
{
    if (!result || (left != 0u && right > SIZE_MAX / left)) return 0;
    *result = left * right;
    return 1;
}

static int resource_range(size_t offset, size_t length, size_t limit)
{
    size_t end;
    return resource_add(offset, length, &end) && end <= limit;
}

static int resource_zero(const uint32_t* values, size_t count)
{
    size_t index;
    for (index = 0u; index < count; ++index) {
        if (values[index] != 0u) return 0;
    }
    return 1;
}

static size_t resource_string_length(const char* string, size_t limit)
{
    size_t length = 0u;
    if (!string) return SIZE_MAX;
    while (length < limit && string[length] != '\0') ++length;
    return length < limit ? length : SIZE_MAX;
}

static int resource_string_valid(const RinResourceView* view, uint32_t offset)
{
    if (!view || !view->header || offset >= view->header->string_table_size) {
        return 0;
    }
    return resource_string_length(view->strings + offset,
                                  view->header->string_table_size - offset) != SIZE_MAX;
}

const char* rin_resource_string(const RinResourceView* view, uint32_t offset)
{
    return resource_string_valid(view, offset) ? view->strings + offset : NULL;
}

static int resource_png_crc32(const uint8_t* bytes, size_t size, uint32_t* crc_out)
{
    uint32_t crc = UINT32_C(0xFFFFFFFF);
    size_t index;
    if (!bytes || !crc_out) return 0;
    for (index = 0u; index < size; ++index) {
        uint32_t value = crc ^ bytes[index];
        uint32_t bit;
        for (bit = 0u; bit < 8u; ++bit)
            value = (value >> 1u) ^ (UINT32_C(0xEDB88320) & (0u - (value & 1u)));
        crc = value;
    }
    *crc_out = crc ^ UINT32_C(0xFFFFFFFF);
    return 1;
}

static uint32_t resource_be32(const uint8_t* bytes)
{
    return ((uint32_t)bytes[0] << 24u) | ((uint32_t)bytes[1] << 16u) |
           ((uint32_t)bytes[2] << 8u) | (uint32_t)bytes[3];
}

static int resource_png_valid(const uint8_t* bytes, size_t size,
                              uint16_t expected_width, uint16_t expected_height)
{
    static const uint8_t signature[RIN_RESOURCE_PNG_SIGNATURE_SIZE] = {
        0x89u, 0x50u, 0x4Eu, 0x47u, 0x0Du, 0x0Au, 0x1Au, 0x0Au
    };
    size_t offset = RIN_RESOURCE_PNG_SIGNATURE_SIZE;
    uint32_t width = 0u;
    uint32_t height = 0u;
    uint32_t idat_count = 0u;
    int have_ihdr = 0;
    int have_iend = 0;

    if (!bytes || size < sizeof(signature) || size > RIN_ICON_IMAGE_MAX_BYTES)
        return 0;
    for (width = 0u; width < sizeof(signature); ++width) {
        if (bytes[width] != signature[width]) return 0;
    }
    while (offset < size) {
        uint32_t length;
        uint32_t stored_crc;
        uint32_t calculated_crc;
        size_t chunk_end;
        if (!resource_range(offset, 12u, size)) return 0;
        length = resource_be32(bytes + offset);
        if (length > RIN_ICON_IMAGE_MAX_BYTES ||
            !resource_add(offset, 12u + (size_t)length, &chunk_end) ||
            chunk_end > size) return 0;
        if (offset + 4u + 4u > size) return 0;
        stored_crc = resource_be32(bytes + offset + 8u + length);
        if (!resource_png_crc32(bytes + offset + 4u, 4u + length,
                                &calculated_crc) || stored_crc != calculated_crc) {
            return 0;
        }
        if (bytes[offset + 4u] == 'I' && bytes[offset + 5u] == 'H' &&
            bytes[offset + 6u] == 'D' && bytes[offset + 7u] == 'R') {
            if (have_ihdr || length != 13u) return 0;
            width = resource_be32(bytes + offset + 8u);
            height = resource_be32(bytes + offset + 12u);
            if (width == 0u || height == 0u || width > RIN_ICON_IMAGE_MAX_DIMENSION ||
                height > RIN_ICON_IMAGE_MAX_DIMENSION || width != expected_width ||
                height != expected_height || bytes[offset + 16u] != 8u ||
                (bytes[offset + 17u] != 2u && bytes[offset + 17u] != 3u &&
                 bytes[offset + 17u] != 4u && bytes[offset + 17u] != 6u) ||
                bytes[offset + 18u] != 0u || bytes[offset + 19u] != 0u ||
                bytes[offset + 20u] != 0u) return 0;
            have_ihdr = 1;
        } else if (bytes[offset + 4u] == 'I' && bytes[offset + 5u] == 'D' &&
                   bytes[offset + 6u] == 'A' && bytes[offset + 7u] == 'T') {
            if (!have_ihdr) return 0;
            ++idat_count;
        } else if (bytes[offset + 4u] == 'I' && bytes[offset + 5u] == 'E' &&
                   bytes[offset + 6u] == 'N' && bytes[offset + 7u] == 'D') {
            if (length != 0u || !have_ihdr || idat_count == 0u || have_iend ||
                chunk_end != size) return 0;
            have_iend = 1;
        }
        offset = chunk_end;
        if (have_iend) break;
    }
    return have_ihdr && have_iend && idat_count != 0u;
}

RinResourceResult rin_resource_validate(const void* section, size_t section_size,
                                        RinResourceView* view)
{
    const uint8_t* bytes = (const uint8_t*)section;
    const RinResourceHeaderV1* header;
    size_t table_size;
    size_t table_end;
    size_t string_end;
    uint32_t index;
    if (view != NULL) memset(view, 0, sizeof(*view));
    if (!bytes || !view || section_size < sizeof(RinResourceHeaderV1) ||
        section_size > RIN_RESOURCE_MAX_SECTION_SIZE) {
        return RIN_RESOURCE_INVALID_ARGUMENT;
    }
    header = (const RinResourceHeaderV1*)bytes;
    if (header->magic != RIN_RESOURCE_MAGIC) return RIN_RESOURCE_INVALID_LAYOUT;
    if (header->version != RIN_RESOURCE_VERSION_1 ||
        header->header_size != sizeof(RinResourceHeaderV1)) {
        return RIN_RESOURCE_UNSUPPORTED_VERSION;
    }
    if (header->section_size != section_size || header->resource_count == 0u ||
        header->resource_count > RIN_RESOURCE_MAX_COUNT ||
        header->resource_entry_size != sizeof(RinResourceEntryV1) ||
        (header->namespace_id != RIN_RESOURCE_NAMESPACE_APPLICATION &&
         header->namespace_id != RIN_RESOURCE_NAMESPACE_SYSTEM) ||
        (header->flags & ~RIN_RESOURCE_FLAG_REQUIRED) != 0u || header->reserved != 0u ||
        header->string_table_size == 0u ||
        !resource_mul(header->resource_count, header->resource_entry_size, &table_size) ||
        !resource_add(header->resource_table_offset, table_size, &table_end) ||
        !resource_add(header->string_table_offset, header->string_table_size, &string_end) ||
        header->resource_table_offset < sizeof(RinResourceHeaderV1) ||
        table_end > section_size || header->string_table_offset < table_end ||
        string_end > section_size ||
        header->string_table_offset < header->resource_table_offset + table_size ||
        bytes[header->string_table_offset] != '\0') {
        return RIN_RESOURCE_INVALID_LAYOUT;
    }
    view->bytes = bytes;
    view->size = section_size;
    view->header = header;
    view->entries = (const RinResourceEntryV1*)(bytes + header->resource_table_offset);
    view->strings = (const char*)(bytes + header->string_table_offset);
    for (index = 0u; index < header->resource_count; ++index) {
        const RinResourceEntryV1* entry = &view->entries[index];
        size_t data_end;
        uint32_t prior;
        if (entry->type == RIN_RESOURCE_INVALID ||
            (entry->flags & ~UINT16_C(1)) != 0u || !resource_string_valid(view, entry->name_offset) ||
            entry->data_size == 0u || entry->data_offset < string_end ||
            !resource_add(entry->data_offset, entry->data_size, &data_end) ||
            data_end > section_size || !resource_zero(entry->reserved, 3u)) {
            return RIN_RESOURCE_INVALID_LAYOUT;
        }
        for (prior = 0u; prior < index; ++prior) {
            if (view->entries[prior].type == entry->type &&
                view->entries[prior].resource_id == entry->resource_id &&
                entry->resource_id != 0u) return RIN_RESOURCE_INVALID_LAYOUT;
        }
    }
    return RIN_RESOURCE_OK;
}

RinResourceResult rin_resource_find(const RinResourceView* view,
                                    uint16_t type, uint32_t resource_id,
                                    const char* name,
                                    const RinResourceEntryV1** entry_out)
{
    uint32_t index;
    if (entry_out != NULL) *entry_out = NULL;
    if (!view || !view->header || !entry_out || type == RIN_RESOURCE_INVALID) {
        return RIN_RESOURCE_INVALID_ARGUMENT;
    }
    for (index = 0u; index < view->header->resource_count; ++index) {
        const RinResourceEntryV1* entry = &view->entries[index];
        const char* entry_name = rin_resource_string(view, entry->name_offset);
        size_t name_length;
        size_t entry_length;
        if (entry->type != type || (resource_id != 0u && entry->resource_id != resource_id)) {
            continue;
        }
        if (!name || name[0] == '\0') {
            *entry_out = entry;
            return RIN_RESOURCE_OK;
        }
        name_length = resource_string_length(name, 256u);
        entry_length = resource_string_length(entry_name, view->header->string_table_size);
        if (name_length != SIZE_MAX && entry_length == name_length) {
            size_t i;
            for (i = 0u; i < name_length; ++i)
                if (name[i] != entry_name[i]) break;
            if (i == name_length) {
                *entry_out = entry;
                return RIN_RESOURCE_OK;
            }
        }
    }
    return RIN_RESOURCE_NOT_FOUND;
}

RinResourceResult rin_resource_icon_open(const RinResourceView* view,
                                         const RinResourceEntryV1* entry,
                                         RinIconResourceView* icon_view)
{
    const uint8_t* bytes;
    const RinIconResourceV1* header;
    size_t table_size;
    size_t table_end;
    uint32_t index;
    if (icon_view != NULL) memset(icon_view, 0, sizeof(*icon_view));
    if (!view || !entry || !icon_view || entry->type != RIN_RESOURCE_ICON ||
        entry->data_offset > view->size || entry->data_size > view->size - entry->data_offset) {
        return RIN_RESOURCE_INVALID_ARGUMENT;
    }
    bytes = view->bytes + entry->data_offset;
    header = (const RinIconResourceV1*)bytes;
    if (entry->data_size < sizeof(RinIconResourceV1) ||
        header->version != RIN_ICON_RESOURCE_VERSION_1 ||
        header->header_size != sizeof(RinIconResourceV1) || header->image_count == 0u ||
        header->image_count > RIN_RESOURCE_MAX_COUNT ||
        header->image_entry_size != sizeof(RinIconImageV1) ||
        !resource_mul(header->image_count, header->image_entry_size, &table_size) ||
        !resource_add(header->image_table_offset, table_size, &table_end) ||
        header->image_table_offset < sizeof(RinIconResourceV1) ||
        table_end > entry->data_size || !resource_zero(header->reserved, 3u)) {
        return RIN_RESOURCE_INVALID_LAYOUT;
    }
    icon_view->bytes = bytes;
    icon_view->size = entry->data_size;
    icon_view->header = header;
    icon_view->images = (const RinIconImageV1*)(bytes + header->image_table_offset);
    for (index = 0u; index < header->image_count; ++index) {
        const RinIconImageV1* image = &icon_view->images[index];
        size_t data_end;
        uint64_t raw_size;
        if (image->width == 0u || image->height == 0u ||
            image->width > RIN_ICON_IMAGE_MAX_DIMENSION ||
            image->height > RIN_ICON_IMAGE_MAX_DIMENSION ||
            image->scale_numerator == 0u || image->scale_denominator == 0u ||
            image->format == RIN_ICON_FORMAT_INVALID ||
            (image->format != RIN_ICON_FORMAT_PNG && image->format != RIN_ICON_FORMAT_BGRA8888) ||
            image->data_offset < table_end || image->data_size == 0u ||
            image->data_size > RIN_ICON_IMAGE_MAX_BYTES ||
            !resource_add(image->data_offset, image->data_size, &data_end) ||
            data_end > entry->data_size || !resource_zero(image->reserved, 3u)) {
            return RIN_RESOURCE_INVALID_LAYOUT;
        }
        if (image->format == RIN_ICON_FORMAT_BGRA8888) {
            raw_size = (uint64_t)image->width * image->height * 4u;
            if (raw_size != image->data_size) return RIN_RESOURCE_INVALID_LAYOUT;
        } else if (!resource_png_valid(bytes + image->data_offset, image->data_size,
                                       image->width, image->height)) {
            return RIN_RESOURCE_INVALID_LAYOUT;
        }
    }
    return RIN_RESOURCE_OK;
}

static uint64_t icon_effective_width(const RinIconImageV1* image)
{
    return (uint64_t)image->width * image->scale_numerator / image->scale_denominator;
}

static uint64_t icon_effective_height(const RinIconImageV1* image)
{
    return (uint64_t)image->height * image->scale_numerator / image->scale_denominator;
}

RinResourceResult rin_resource_icon_select(const RinIconResourceView* icon_view,
                                           uint32_t requested_width,
                                           uint32_t requested_height,
                                           uint16_t requested_scale_numerator,
                                           uint16_t requested_scale_denominator,
                                           RinIconImageView* image_out)
{
    const RinIconImageV1* selected = NULL;
    uint64_t desired_width;
    uint64_t desired_height;
    int selected_above = 0;
    uint32_t index;
    if (image_out != NULL) memset(image_out, 0, sizeof(*image_out));
    if (!icon_view || !icon_view->header || !image_out || requested_width == 0u ||
        requested_height == 0u || requested_scale_numerator == 0u ||
        requested_scale_denominator == 0u) return RIN_RESOURCE_INVALID_ARGUMENT;
    desired_width = (uint64_t)requested_width * requested_scale_numerator /
                    requested_scale_denominator;
    desired_height = (uint64_t)requested_height * requested_scale_numerator /
                     requested_scale_denominator;
    for (index = 0u; index < icon_view->header->image_count; ++index) {
        const RinIconImageV1* candidate = &icon_view->images[index];
        uint64_t width = icon_effective_width(candidate);
        uint64_t height = icon_effective_height(candidate);
        int above = width >= desired_width && height >= desired_height;
        int better = 0;
        if (!selected) better = 1;
        else if (above != selected_above) better = above;
        else if (above) {
            uint64_t candidate_gap = (width - desired_width) + (height - desired_height);
            uint64_t selected_gap = (icon_effective_width(selected) - desired_width) +
                                     (icon_effective_height(selected) - desired_height);
            better = candidate_gap < selected_gap ||
                     (candidate_gap == selected_gap && candidate->data_size < selected->data_size);
        } else {
            better = width + height > icon_effective_width(selected) +
                     icon_effective_height(selected);
        }
        if (better) {
            selected = candidate;
            selected_above = above;
        }
    }
    if (!selected) return RIN_RESOURCE_NOT_FOUND;
    image_out->metadata = selected;
    image_out->bytes = icon_view->bytes + selected->data_offset;
    image_out->size = selected->data_size;
    return RIN_RESOURCE_OK;
}

RinResourceResult rin_resource_locate_image(const void* image_prefix,
                                            size_t prefix_size,
                                            RinResourceImageLocation* location)
{
    const uint8_t* bytes = (const uint8_t*)image_prefix;
    const RinHeaderV3* header;
    size_t table_size;
    uint32_t index;
    uint32_t resource_count = 0u;
    RinResourceImageLocation candidate = {0u, 0u};
    if (location != NULL) memset(location, 0, sizeof(*location));
    if (!bytes || !location || prefix_size < sizeof(RinHeaderV3))
        return RIN_RESOURCE_INVALID_ARGUMENT;
    header = (const RinHeaderV3*)bytes;
    if (header->magic != RIN_IMAGE_MAGIC || header->version != RIN_IMAGE_VERSION_3 ||
        header->header_size != sizeof(RinHeaderV3) || header->section_count == 0u ||
        header->section_count > 32u || !resource_mul(header->section_count,
        sizeof(RinSectionV3), &table_size) || header->section_table_offset < sizeof(*header) ||
        header->section_table_offset > prefix_size || table_size > prefix_size -
        header->section_table_offset) {
        return RIN_RESOURCE_INVALID_LAYOUT;
    }
    for (index = 0u; index < header->section_count; ++index) {
        const RinSectionV3* section = (const RinSectionV3*)(bytes +
            header->section_table_offset + index * sizeof(RinSectionV3));
        if (section->type != RIN_IMAGE_SECTION_RESOURCES) continue;
        ++resource_count;
        if (resource_count > 1u || section->file_size == 0u ||
            section->file_offset < sizeof(RinHeaderV3) ||
            section->alignment < 8u || section->memory_size != 0u ||
            section->flags != RIN_IMAGE_SECTION_READ ||
            section->file_size > RIN_RESOURCE_MAX_SECTION_SIZE) {
            return RIN_RESOURCE_INVALID_LAYOUT;
        }
        candidate.file_offset = section->file_offset;
        candidate.file_size = section->file_size;
    }
    if (resource_count != 1u) return RIN_RESOURCE_NOT_FOUND;
    *location = candidate;
    return RIN_RESOURCE_OK;
}

RinResourceResult rin_resource_open_image(const void* image, size_t image_size,
                                          RinResourceView* view)
{
    const uint8_t* bytes = (const uint8_t*)image;
    const RinHeaderV3* header;
    RinResourceImageLocation location;
    if (view != NULL) memset(view, 0, sizeof(*view));
    if (!bytes || !view || image_size < sizeof(RinHeaderV3))
        return RIN_RESOURCE_INVALID_ARGUMENT;
    header = (const RinHeaderV3*)bytes;
    if (header->section_count == 0u || header->section_count > 32u ||
        header->section_table_offset > image_size ||
        (uint64_t)header->section_count * sizeof(RinSectionV3) >
            image_size - header->section_table_offset) {
        return RIN_RESOURCE_INVALID_LAYOUT;
    }
    {
        RinResourceResult locate_result = rin_resource_locate_image(
            bytes, (size_t)(header->section_table_offset +
                            header->section_count * sizeof(RinSectionV3)),
            &location);
        if (locate_result != RIN_RESOURCE_OK) return locate_result;
    }
    if (location.file_offset > image_size ||
        location.file_size > image_size - location.file_offset)
        return RIN_RESOURCE_INVALID_LAYOUT;
    return rin_resource_validate(bytes + location.file_offset,
                                 (size_t)location.file_size, view);
}
