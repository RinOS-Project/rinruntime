/* SPDX-License-Identifier: MIT */
/* Bounded reader for authenticated RIN v3 resource sections. */
#ifndef RIN_SHARED_RESOURCE_H
#define RIN_SHARED_RESOURCE_H

#include <stddef.h>
#include <stdint.h>

#include <rin/formats_v3.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum RinResourceResult {
    RIN_RESOURCE_OK = 0,
    RIN_RESOURCE_INVALID_ARGUMENT = -1,
    RIN_RESOURCE_INVALID_LAYOUT = -2,
    RIN_RESOURCE_UNSUPPORTED_VERSION = -3,
    RIN_RESOURCE_NOT_FOUND = -4,
    RIN_RESOURCE_UNSUPPORTED_FORMAT = -5
} RinResourceResult;

typedef struct RinResourceView {
    const uint8_t* bytes;
    size_t size;
    const RinResourceHeaderV1* header;
    const RinResourceEntryV1* entries;
    const char* strings;
} RinResourceView;

typedef struct RinIconResourceView {
    const uint8_t* bytes;
    size_t size;
    const RinIconResourceV1* header;
    const RinIconImageV1* images;
} RinIconResourceView;

typedef struct RinIconImageView {
    const RinIconImageV1* metadata;
    const uint8_t* bytes;
    uint32_t size;
} RinIconImageView;

typedef struct RinResourceImageLocation {
    uint64_t file_offset;
    uint64_t file_size;
} RinResourceImageLocation;

/* Validate a complete resource section without allocating or trusting any
 * pointer/offset supplied by the image. */
RinResourceResult rin_resource_validate(const void* section, size_t section_size,
                                        RinResourceView* view);

/* Locate an entry by type and id.  A non-empty name additionally constrains
 * the match; this permits stable ids with human-readable metadata names. */
RinResourceResult rin_resource_find(const RinResourceView* view,
                                    uint16_t type, uint32_t resource_id,
                                    const char* name,
                                    const RinResourceEntryV1** entry_out);

RinResourceResult rin_resource_icon_open(const RinResourceView* view,
                                         const RinResourceEntryV1* entry,
                                         RinIconResourceView* icon_view);

/* Select the smallest image at or above the requested effective size.  If no
 * such image exists, select the largest available image below it. */
RinResourceResult rin_resource_icon_select(const RinIconResourceView* icon_view,
                                           uint32_t requested_width,
                                           uint32_t requested_height,
                                           uint16_t requested_scale_numerator,
                                           uint16_t requested_scale_denominator,
                                           RinIconImageView* image_out);

/* Validate a standalone RIN v3 image and expose only its resource section.
 * Signature verification remains a separate policy operation. */
RinResourceResult rin_resource_open_image(const void* image, size_t image_size,
                                          RinResourceView* view);

/* Locate the resource section from a bounded header+section-table prefix.
 * Callers can then read only the returned byte range instead of copying the
 * executable into memory. */
RinResourceResult rin_resource_locate_image(const void* image_prefix,
                                            size_t prefix_size,
                                            RinResourceImageLocation* location);

const char* rin_resource_string(const RinResourceView* view, uint32_t offset);

#ifdef __cplusplus
}
#endif

#endif /* RIN_SHARED_RESOURCE_H */
