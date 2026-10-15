/* SPDX-License-Identifier: MIT */

#include <rin/crash_region.h>

#include <stddef.h>

static void region_zero(void* output, uint32_t size)
{
    uint8_t* bytes = (uint8_t*)output;
    uint32_t index;
    for (index = 0u; index < size; ++index) bytes[index] = 0u;
}

static void region_copy(void* output, const void* input, uint32_t size)
{
    uint8_t* destination = (uint8_t*)output;
    const uint8_t* source = (const uint8_t*)input;
    uint32_t index;
    for (index = 0u; index < size; ++index) destination[index] = source[index];
}

static int region_bytes_nonzero(const uint8_t* bytes, uint32_t size)
{
    uint8_t combined = 0u;
    uint32_t index;
    for (index = 0u; index < size; ++index) combined |= bytes[index];
    return combined != 0u;
}

static int region_bytes_equal(const uint8_t* left, const uint8_t* right,
                              uint32_t size)
{
    uint8_t difference = 0u;
    uint32_t index;
    for (index = 0u; index < size; ++index)
        difference |= left[index] ^ right[index];
    return difference == 0u;
}

static uint32_t region_crc32_update(uint32_t crc, const uint8_t* bytes,
                                    uint32_t size)
{
    uint32_t index;
    for (index = 0u; index < size; ++index) {
        uint32_t bit;
        crc ^= bytes[index];
        for (bit = 0u; bit < 8u; ++bit) {
            uint32_t mask = UINT32_C(0) - (crc & UINT32_C(1));
            crc = (crc >> 1u) ^ (UINT32_C(0xedb88320) & mask);
        }
    }
    return crc;
}

static uint32_t region_descriptor_crc(const uint8_t* bytes)
{
    static const uint8_t zeros[4] = {0u, 0u, 0u, 0u};
    const uint32_t offset =
        (uint32_t)offsetof(RinCrashRegionDescriptorV1, crc32);
    uint32_t crc = UINT32_C(0xffffffff);
    crc = region_crc32_update(crc, bytes, offset);
    crc = region_crc32_update(crc, zeros, sizeof(zeros));
    crc = region_crc32_update(
        crc, bytes + offset + sizeof(uint32_t),
        RIN_CRASH_REGION_DESCRIPTOR_SIZE - offset - sizeof(uint32_t));
    return ~crc;
}

int rin_crash_region_binding_valid(const RinCrashRegionBinding* binding)
{
    uint64_t region_end =
        RIN_CRASH_REGION_FIRST_LBA + RIN_CRASH_REGION_SECTOR_COUNT;
    return binding && binding->reserved == 0u &&
           binding->logical_block_size ==
               RIN_CRASH_REGION_LOGICAL_BLOCK_SIZE &&
           binding->block_count >= region_end &&
           binding->block_count > RIN_CRASH_REGION_FIRST_PARTITION_LBA &&
           region_bytes_nonzero(binding->disk_guid,
                                sizeof(binding->disk_guid)) &&
           region_bytes_nonzero(binding->install_nonce,
                                sizeof(binding->install_nonce));
}

int rin_crash_region_binding_matches(const RinCrashRegionBinding* expected,
                                     const RinCrashRegionBinding* observed)
{
    return rin_crash_region_binding_valid(expected) &&
           rin_crash_region_binding_valid(observed) &&
           expected->block_count == observed->block_count &&
           expected->logical_block_size == observed->logical_block_size &&
           region_bytes_equal(expected->disk_guid, observed->disk_guid,
                              sizeof(expected->disk_guid)) &&
           region_bytes_equal(expected->install_nonce,
                              observed->install_nonce,
                              sizeof(expected->install_nonce));
}

RinCrashRegionResult rin_crash_region_descriptor_encode(
    const RinCrashRegionBinding* binding,
    uint8_t output[RIN_CRASH_REGION_DESCRIPTOR_SIZE])
{
    RinCrashRegionDescriptorV1 descriptor;
    if (!output || !rin_crash_region_binding_valid(binding))
        return RIN_CRASH_REGION_INVALID;
    region_zero(output, RIN_CRASH_REGION_DESCRIPTOR_SIZE);
    region_zero(&descriptor, sizeof(descriptor));
    descriptor.magic = RIN_CRASH_REGION_MAGIC;
    descriptor.version = RIN_CRASH_REGION_VERSION;
    descriptor.header_size = sizeof(descriptor);
    descriptor.total_size = RIN_CRASH_REGION_DESCRIPTOR_SIZE;
    descriptor.state = RIN_CRASH_REGION_STATE_ACTIVE;
    descriptor.block_count = binding->block_count;
    descriptor.region_first_lba = RIN_CRASH_REGION_FIRST_LBA;
    descriptor.region_sector_count = RIN_CRASH_REGION_SECTOR_COUNT;
    descriptor.logical_block_size = binding->logical_block_size;
    descriptor.slot_size = RIN_CRASH_REGION_SLOT_SIZE;
    descriptor.slot_count = RIN_CRASH_REGION_SLOT_COUNT;
    region_copy(descriptor.disk_guid, binding->disk_guid,
                sizeof(descriptor.disk_guid));
    region_copy(descriptor.install_nonce, binding->install_nonce,
                sizeof(descriptor.install_nonce));
    region_copy(output, &descriptor, sizeof(descriptor));
    descriptor.crc32 = region_descriptor_crc(output);
    region_copy(output, &descriptor, sizeof(descriptor));
    return RIN_CRASH_REGION_OK;
}

RinCrashRegionResult rin_crash_region_descriptor_decode(
    const uint8_t input[RIN_CRASH_REGION_DESCRIPTOR_SIZE],
    RinCrashRegionBinding* binding)
{
    return rin_crash_region_descriptor_decode_layout(input, binding, NULL);
}

RinCrashRegionResult rin_crash_region_descriptor_decode_layout(
    const uint8_t input[RIN_CRASH_REGION_DESCRIPTOR_SIZE],
    RinCrashRegionBinding* binding, RinCrashRegionPanicLayout* layout)
{
    RinCrashRegionDescriptorV1 descriptor;
    RinCrashRegionBinding observed;
    RinCrashRegionPanicLayout observed_layout;
    uint32_t expected_slot_count;
    uint32_t expected_slot_size;
    uint64_t expected_first_lba;
    uint64_t expected_region_sectors;
    uint32_t index;
    if (binding) region_zero(binding, sizeof(*binding));
    if (layout) region_zero(layout, sizeof(*layout));
    if (!input || !binding) return RIN_CRASH_REGION_INVALID;
    region_copy(&descriptor, input, sizeof(descriptor));
    if (descriptor.version == RIN_CRASH_REGION_LEGACY_VERSION) {
        expected_slot_count = RIN_CRASH_REGION_LEGACY_SLOT_COUNT;
        expected_slot_size = RIN_CRASH_REGION_LEGACY_SLOT_SIZE;
        expected_first_lba = RIN_CRASH_REGION_LEGACY_FIRST_LBA;
    } else if (descriptor.version == RIN_CRASH_REGION_V2_VERSION) {
        expected_slot_count = RIN_CRASH_REGION_V2_SLOT_COUNT;
        expected_slot_size = RIN_CRASH_REGION_V2_SLOT_SIZE;
        expected_first_lba = RIN_CRASH_REGION_FIRST_LBA;
    } else if (descriptor.version == RIN_CRASH_REGION_V3_VERSION) {
        expected_slot_count = RIN_CRASH_REGION_V3_SLOT_COUNT;
        expected_slot_size = RIN_CRASH_REGION_SLOT_SIZE;
        expected_first_lba = RIN_CRASH_REGION_FIRST_LBA;
    } else if (descriptor.version == RIN_CRASH_REGION_VERSION) {
        expected_slot_count = RIN_CRASH_REGION_SLOT_COUNT;
        expected_slot_size = RIN_CRASH_REGION_SLOT_SIZE;
        expected_first_lba = RIN_CRASH_REGION_FIRST_LBA;
    } else {
        return RIN_CRASH_REGION_CORRUPT;
    }
    if (descriptor.version == RIN_CRASH_REGION_LEGACY_VERSION) {
        expected_region_sectors = RIN_CRASH_REGION_LEGACY_SECTOR_COUNT;
    } else if (descriptor.version == RIN_CRASH_REGION_V2_VERSION) {
        expected_region_sectors = RIN_CRASH_REGION_V2_SECTOR_COUNT;
    } else if (descriptor.version == RIN_CRASH_REGION_V3_VERSION) {
        expected_region_sectors = RIN_CRASH_REGION_V3_SECTOR_COUNT;
    } else {
        expected_region_sectors = RIN_CRASH_REGION_SECTOR_COUNT;
    }
    if (descriptor.magic != RIN_CRASH_REGION_MAGIC ||
        descriptor.header_size != sizeof(descriptor) ||
        descriptor.total_size != RIN_CRASH_REGION_DESCRIPTOR_SIZE ||
        descriptor.state != RIN_CRASH_REGION_STATE_ACTIVE ||
        descriptor.region_first_lba != expected_first_lba ||
        descriptor.region_sector_count != expected_region_sectors ||
        descriptor.logical_block_size !=
            RIN_CRASH_REGION_LOGICAL_BLOCK_SIZE ||
        descriptor.slot_size != expected_slot_size ||
        descriptor.slot_count != expected_slot_count ||
        descriptor.reserved0 != 0u || descriptor.reserved1 != 0u ||
        descriptor.crc32 != region_descriptor_crc(input)) {
        return RIN_CRASH_REGION_CORRUPT;
    }
    for (index = sizeof(descriptor);
         index < RIN_CRASH_REGION_DESCRIPTOR_SIZE; ++index) {
        if (input[index] != 0u) return RIN_CRASH_REGION_CORRUPT;
    }
    region_zero(&observed, sizeof(observed));
    observed.block_count = descriptor.block_count;
    observed.logical_block_size = descriptor.logical_block_size;
    region_copy(observed.disk_guid, descriptor.disk_guid,
                sizeof(observed.disk_guid));
    region_copy(observed.install_nonce, descriptor.install_nonce,
                sizeof(observed.install_nonce));
    if (!rin_crash_region_binding_valid(&observed))
        return RIN_CRASH_REGION_CORRUPT;
    if (rin_crash_region_panic_layout_for_slots(
            &observed, descriptor.region_first_lba, descriptor.slot_size,
            descriptor.slot_count, &observed_layout) != RIN_CRASH_REGION_OK) {
        return RIN_CRASH_REGION_CORRUPT;
    }
    region_copy(binding, &observed, sizeof(observed));
    if (layout) region_copy(layout, &observed_layout, sizeof(observed_layout));
    return RIN_CRASH_REGION_OK;
}

RinCrashRegionResult rin_crash_region_validate_partition_ranges(
    const RinCrashRegionBinding* binding,
    const RinCrashRegionPartitionRange* ranges, uint32_t range_count)
{
    uint64_t reserved_first = RIN_CRASH_REGION_FIRST_LBA;
    uint64_t reserved_last = reserved_first +
                             RIN_CRASH_REGION_SECTOR_COUNT - 1u;
    uint64_t legacy_first = RIN_CRASH_REGION_LEGACY_FIRST_LBA;
    uint64_t legacy_last = legacy_first +
                           RIN_CRASH_REGION_LEGACY_SECTOR_COUNT - 1u;
    uint32_t index;
    if (!rin_crash_region_binding_valid(binding) || !ranges ||
        range_count == 0u || range_count > 4096u) {
        return RIN_CRASH_REGION_INVALID;
    }
    for (index = 0u; index < range_count; ++index) {
        if (ranges[index].first_lba > ranges[index].last_lba ||
            ranges[index].last_lba >= binding->block_count) {
            return RIN_CRASH_REGION_RANGE;
        }
        if (!(ranges[index].last_lba < reserved_first ||
              ranges[index].first_lba > reserved_last) ||
            !(ranges[index].last_lba < legacy_first ||
              ranges[index].first_lba > legacy_last)) {
            return RIN_CRASH_REGION_MISMATCH;
        }
    }
    return RIN_CRASH_REGION_OK;
}

RinCrashRegionResult rin_crash_region_panic_layout(
    const RinCrashRegionBinding* binding, RinCrashRegionPanicLayout* layout)
{
    return rin_crash_region_panic_layout_for_slots(
        binding, RIN_CRASH_REGION_FIRST_LBA, RIN_CRASH_REGION_SLOT_SIZE,
        RIN_CRASH_REGION_SLOT_COUNT, layout);
}

RinCrashRegionResult rin_crash_region_panic_layout_for_slots(
    const RinCrashRegionBinding* binding, uint64_t region_first_lba,
    uint32_t slot_size, uint32_t slot_count,
    RinCrashRegionPanicLayout* layout)
{
    uint64_t byte_size;
    uint64_t maximum_count;
    if (layout) region_zero(layout, sizeof(*layout));
    if (!layout || !rin_crash_region_binding_valid(binding) ||
        (region_first_lba != RIN_CRASH_REGION_FIRST_LBA &&
         region_first_lba != RIN_CRASH_REGION_LEGACY_FIRST_LBA) ||
        slot_size == 0u || slot_count < 2u ||
        slot_count > RIN_CRASH_REGION_SLOT_COUNT ||
        slot_count > UINT32_MAX / slot_size) {
        return RIN_CRASH_REGION_INVALID;
    }
    if (region_first_lba == RIN_CRASH_REGION_LEGACY_FIRST_LBA) {
        if (slot_size != RIN_CRASH_REGION_LEGACY_SLOT_SIZE) {
            return RIN_CRASH_REGION_INVALID;
        }
        maximum_count = RIN_CRASH_REGION_LEGACY_SLOT_COUNT;
    } else if (slot_size == RIN_CRASH_REGION_V2_SLOT_SIZE) {
        maximum_count = RIN_CRASH_REGION_V2_SLOT_COUNT;
    } else if (slot_size == RIN_CRASH_REGION_SLOT_SIZE) {
        maximum_count = RIN_CRASH_REGION_SLOT_COUNT;
    } else {
        return RIN_CRASH_REGION_INVALID;
    }
    if (slot_count > maximum_count) return RIN_CRASH_REGION_INVALID;
    maximum_count = (RIN_CRASH_REGION_FIRST_PARTITION_LBA -
        region_first_lba - RIN_CRASH_REGION_DESCRIPTOR_SECTORS) *
        RIN_CRASH_REGION_LOGICAL_BLOCK_SIZE / slot_size;
    if (slot_count > maximum_count) return RIN_CRASH_REGION_INVALID;
    byte_size = (uint64_t)slot_size * slot_count;
    layout->byte_offset = (region_first_lba +
                           RIN_CRASH_REGION_DESCRIPTOR_SECTORS) *
                          binding->logical_block_size;
    layout->byte_size = byte_size;
    layout->slot_size = slot_size;
    layout->slot_count = slot_count;
    return RIN_CRASH_REGION_OK;
}
