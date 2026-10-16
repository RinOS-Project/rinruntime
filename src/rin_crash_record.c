/* SPDX-License-Identifier: MIT */

#include <rin/crash_record.h>

#include <stddef.h>

static void crash_zero(void* output, uint32_t size)
{
    uint8_t* bytes = (uint8_t*)output;
    uint32_t index;
    for (index = 0u; index < size; ++index) bytes[index] = 0u;
}

static void crash_copy(void* output, const void* input, uint32_t size)
{
    uint8_t* destination = (uint8_t*)output;
    const uint8_t* source = (const uint8_t*)input;
    uint32_t index;
    for (index = 0u; index < size; ++index) destination[index] = source[index];
}

static uint32_t crash_crc32(const void* data, uint32_t size)
{
    const uint8_t* bytes = (const uint8_t*)data;
    uint32_t crc = UINT32_C(0xffffffff);
    uint32_t index;
    for (index = 0u; index < size; ++index) {
        uint32_t bit;
        crc ^= bytes[index];
        for (bit = 0u; bit < 8u; ++bit) {
            uint32_t mask = UINT32_C(0) - (crc & UINT32_C(1));
            crc = (crc >> 1u) ^ (UINT32_C(0xedb88320) & mask);
        }
    }
    return ~crc;
}

static uint32_t crash_header_crc(const RinCrashRecordHeader* header)
{
    RinCrashRecordHeader copy = *header;
    copy.header_crc32 = 0u;
    return crash_crc32(&copy, sizeof(copy));
}

static int crash_kind_valid(uint32_t kind)
{
    return kind == RIN_CRASH_RECORD_KERNEL_PANIC ||
           kind == RIN_CRASH_RECORD_USER_MINIDUMP;
}

static int crash_section_size_valid(uint32_t type, uint32_t size)
{
    switch (type) {
        case RIN_CRASH_SECTION_MESSAGE:
            return size > 0u && size <= RIN_CRASH_RECORD_MAX_MESSAGE;
        case RIN_CRASH_SECTION_REGISTERS_X64:
            return size == sizeof(RinCrashRegistersX64);
        case RIN_CRASH_SECTION_REGISTERS_X86:
            return size == sizeof(RinCrashRegistersX86);
        case RIN_CRASH_SECTION_STACKTRACE_X64:
            return size > 0u && (size % sizeof(uint64_t)) == 0u &&
                   size / sizeof(uint64_t) <= RIN_CRASH_RECORD_MAX_FRAMES;
        case RIN_CRASH_SECTION_PROCESS:
            return size == sizeof(RinCrashProcessInfo) ||
                   size == RIN_CRASH_PROCESS_INFO_PRE_SESSION_SIZE ||
                   size == RIN_CRASH_PROCESS_INFO_LEGACY_SIZE;
        case RIN_CRASH_SECTION_SCHEDULER:
            return size == sizeof(RinCrashSchedulerInfo);
        default:
            return 0;
    }
}

static int crash_x64_address_valid(uint64_t address)
{
    uint64_t upper;
    if (address < UINT64_C(0x1000)) return 0;
    upper = address >> 48u;
    return ((address & (UINT64_C(1) << 47u)) == 0u && upper == 0u) ||
           ((address & (UINT64_C(1) << 47u)) != 0u &&
            upper == UINT64_C(0xffff));
}

static int crash_x86_address_valid(uint32_t address)
{
    return address >= UINT32_C(0x1000);
}

static int crash_text_valid(const uint8_t* text, uint32_t size)
{
    uint32_t index = 0u;
    if (!text || size == 0u) return 0;
    while (index < size) {
        uint8_t first = text[index++];
        uint32_t continuation_count;
        uint8_t second;
        if (first < 0x80u) {
            if (first < 0x20u || first == 0x7fu) return 0;
            continue;
        }
        if (first >= 0xc2u && first <= 0xdfu) {
            continuation_count = 1u;
        } else if (first >= 0xe0u && first <= 0xefu) {
            continuation_count = 2u;
        } else if (first >= 0xf0u && first <= 0xf4u) {
            continuation_count = 3u;
        } else {
            return 0;
        }
        if (continuation_count > size - index) return 0;
        second = text[index];
        if ((second & 0xc0u) != 0x80u ||
            (first == 0xe0u && second < 0xa0u) ||
            (first == 0xedu && second >= 0xa0u) ||
            (first == 0xf0u && second < 0x90u) ||
            (first == 0xf4u && second >= 0x90u)) {
            return 0;
        }
        while (continuation_count-- != 0u) {
            if ((text[index++] & 0xc0u) != 0x80u) return 0;
        }
    }
    return 1;
}

static int crash_section_content_valid(uint32_t type, const void* data,
                                       uint32_t size)
{
    uint32_t index;
    if (!data || !crash_section_size_valid(type, size)) return 0;
    if (type == RIN_CRASH_SECTION_MESSAGE) {
        return crash_text_valid((const uint8_t*)data, size);
    }
    if (type == RIN_CRASH_SECTION_REGISTERS_X64) {
        RinCrashRegistersX64 registers;
        crash_copy(&registers, data, sizeof(registers));
        return crash_x64_address_valid(registers.rip);
    }
    if (type == RIN_CRASH_SECTION_REGISTERS_X86) {
        RinCrashRegistersX86 registers;
        crash_copy(&registers, data, sizeof(registers));
        return crash_x86_address_valid(registers.eip) &&
               crash_x86_address_valid(
                   registers.gpr[RIN_CRASH_X86_ESP]);
    }
    if (type == RIN_CRASH_SECTION_STACKTRACE_X64) {
        for (index = 0u; index < size / sizeof(uint64_t); ++index) {
            uint64_t frame;
            crash_copy(&frame, (const uint8_t*)data +
                                   index * sizeof(frame), sizeof(frame));
            if (!crash_x64_address_valid(frame)) return 0;
        }
    } else if (type == RIN_CRASH_SECTION_PROCESS) {
        RinCrashProcessInfo process = {0};
        int terminated = 0;
        uint32_t package_digest_nonzero = 0u;
        crash_copy(&process, data, size);
        if (!crash_x64_address_valid(process.image_base) ||
            process.image_size == 0u ||
            process.image_base > UINT64_MAX - process.image_size) return 0;
        for (index = 0u; index < sizeof(process.image_name); ++index) {
            if (process.image_name[index] == '\0') {
                terminated = index != 0u;
                break;
            }
            if ((uint8_t)process.image_name[index] == 0x7fu ||
                (uint8_t)process.image_name[index] < 0x20u) return 0;
        }
        if (!terminated || !crash_text_valid(
                (const uint8_t*)process.image_name, index))
            return 0;
        if (size >= RIN_CRASH_PROCESS_INFO_PRE_SESSION_SIZE &&
            process.reserved != 0u)
            return 0;
        for (index = 0u; index < sizeof(process.package_digest); ++index)
            package_digest_nonzero |= process.package_digest[index] != 0u;
        if (!((process.package_generation == 0u &&
               package_digest_nonzero == 0u) ||
              (process.package_generation != 0u &&
               package_digest_nonzero != 0u)))
            return 0;
        if (size < sizeof(process)) return 1;
        return rin_crash_owner_session_valid(&process.owner_session,
                                             process.owner_uid);
    } else if (type == RIN_CRASH_SECTION_SCHEDULER) {
        RinCrashSchedulerInfo scheduler;
        crash_copy(&scheduler, data, sizeof(scheduler));
        if (scheduler.struct_size != sizeof(scheduler) ||
            scheduler.version != RIN_CRASH_SCHEDULER_INFO_VERSION ||
            scheduler.reserved != 0u || scheduler.reserved2 != 0u ||
            scheduler.current_valid > 1u ||
            scheduler.current_reserved != 0u ||
            scheduler.cpu_count > RIN_CRASH_SCHEDULER_MAX_CPUS)
            return 0;
        if (scheduler.current_valid != 0u &&
            (scheduler.current_process_id == 0u ||
             scheduler.current_thread_id <= 0 ||
             scheduler.current_process_generation == 0u ||
             scheduler.current_thread_generation == 0u ||
             scheduler.current_cpu >= RIN_CRASH_SCHEDULER_MAX_CPUS))
            return 0;
        for (index = 0u; index < scheduler.cpu_count; ++index) {
            if (scheduler.cpu[index].cpu_index != index)
                return 0;
        }
    }
    return 1;
}

static int crash_draft_has_section(const void* record,
                                   const RinCrashRecordHeader* header,
                                   uint32_t type)
{
    uint32_t offset = sizeof(*header);
    uint32_t index;
    for (index = 0u; index < header->section_count; ++index) {
        RinCrashSectionHeader section;
        uint32_t padded_size;
        if (offset > header->total_size ||
            sizeof(section) > header->total_size - offset) return -1;
        crash_copy(&section, (const uint8_t*)record + offset,
                   sizeof(section));
        if (!crash_section_size_valid(section.type, section.size)) return -1;
        if (section.type == type) return 1;
        padded_size = (section.size + 7u) & ~UINT32_C(7);
        if (padded_size > header->total_size - offset - sizeof(section))
            return -1;
        offset += sizeof(section) + padded_size;
    }
    return offset == header->total_size ? 0 : -1;
}

RinCrashRecordResult rin_crash_record_initialize(
    void* record, uint32_t capacity, uint32_t kind, uint32_t flags,
    uint64_t timestamp_ns, uint64_t boot_id_high, uint64_t boot_id_low,
    uint32_t process_id, uint32_t thread_id, uint32_t exception_code)
{
    return rin_crash_record_initialize_architecture(
        record, capacity, kind, flags, timestamp_ns, boot_id_high, boot_id_low,
        process_id, thread_id, exception_code, RIN_CRASH_ARCH_X86_64);
}

RinCrashRecordResult rin_crash_record_initialize_architecture(
    void* record, uint32_t capacity, uint32_t kind, uint32_t flags,
    uint64_t timestamp_ns, uint64_t boot_id_high, uint64_t boot_id_low,
    uint32_t process_id, uint32_t thread_id, uint32_t exception_code,
    uint32_t architecture)
{
    RinCrashRecordHeader header;
    if (!record || capacity < sizeof(RinCrashRecordHeader) ||
        capacity > RIN_CRASH_RECORD_MAX_SIZE || !crash_kind_valid(kind) ||
        (flags & ~RIN_CRASH_RECORD_FLAG_MASK) != 0u ||
        (flags & RIN_CRASH_RECORD_FLAG_LOCAL_ONLY) == 0u ||
        (kind == RIN_CRASH_RECORD_KERNEL_PANIC &&
         (flags & RIN_CRASH_RECORD_FLAG_USER_MODE) != 0u) ||
        (kind == RIN_CRASH_RECORD_USER_MINIDUMP &&
         (flags & RIN_CRASH_RECORD_FLAG_USER_MODE) == 0u) ||
        (architecture != RIN_CRASH_ARCH_X86_64 &&
         architecture != RIN_CRASH_ARCH_X86_32)) {
        return RIN_CRASH_RECORD_INVALID;
    }
    crash_zero(record, capacity);
    crash_zero(&header, sizeof(header));
    header.magic = RIN_CRASH_RECORD_MAGIC;
    header.version = RIN_CRASH_RECORD_VERSION;
    header.header_size = (uint16_t)sizeof(header);
    header.total_size = sizeof(header);
    header.state = RIN_CRASH_RECORD_DRAFT;
    header.timestamp_ns = timestamp_ns;
    header.boot_id_high = boot_id_high;
    header.boot_id_low = boot_id_low;
    header.kind = kind;
    header.architecture = architecture;
    header.process_id = process_id;
    header.thread_id = thread_id;
    header.exception_code = exception_code;
    header.flags = flags;
    crash_copy(record, &header, sizeof(header));
    return RIN_CRASH_RECORD_OK;
}

RinCrashRecordResult rin_crash_record_add_section(
    void* record, uint32_t capacity, uint32_t type,
    const void* data, uint32_t size)
{
    RinCrashRecordHeader header;
    RinCrashSectionHeader section;
    uint8_t* section_bytes;
    uint32_t padded_size;
    uint32_t required;
    int already_present;
    if (!record || !data || capacity < sizeof(header) ||
        capacity > RIN_CRASH_RECORD_MAX_SIZE) {
        return RIN_CRASH_RECORD_INVALID;
    }
    crash_copy(&header, record, sizeof(header));
    if (header.magic != RIN_CRASH_RECORD_MAGIC ||
        header.version != RIN_CRASH_RECORD_VERSION ||
        header.header_size != sizeof(header) ||
        header.state != RIN_CRASH_RECORD_DRAFT ||
        header.total_size < sizeof(header) ||
        header.total_size > capacity ||
        header.section_count >= RIN_CRASH_RECORD_MAX_SECTIONS) {
        return RIN_CRASH_RECORD_INVALID;
    }
    already_present = crash_draft_has_section(record, &header, type);
    if (already_present != 0 ||
        !crash_section_content_valid(type, data, size)) {
        return RIN_CRASH_RECORD_INVALID;
    }
    padded_size = (size + 7u) & ~UINT32_C(7);
    if (header.total_size > capacity ||
        padded_size > UINT32_MAX - sizeof(section) ||
        header.total_size > UINT32_MAX - sizeof(section) - padded_size) {
        return RIN_CRASH_RECORD_FULL;
    }
    required = header.total_size + sizeof(section) + padded_size;
    if (required > capacity || required > RIN_CRASH_RECORD_MAX_SIZE) {
        return RIN_CRASH_RECORD_FULL;
    }
    section_bytes = (uint8_t*)record + header.total_size;
    crash_zero(section_bytes, sizeof(section) + padded_size);
    crash_zero(&section, sizeof(section));
    section.type = type;
    section.size = size;
    crash_copy(section_bytes, &section, sizeof(section));
    crash_copy(section_bytes + sizeof(section), data, size);
    header.total_size = required;
    header.section_count++;
    crash_copy(record, &header, sizeof(header));
    return RIN_CRASH_RECORD_OK;
}

RinCrashRecordResult rin_crash_record_finalize(
    void* record, uint32_t capacity)
{
    RinCrashRecordHeader header;
    RinCrashRecordHeader draft_header;
    RinCrashRecordResult result;
    if (!record || capacity < sizeof(header) ||
        capacity > RIN_CRASH_RECORD_MAX_SIZE) {
        return RIN_CRASH_RECORD_STATE_ERROR;
    }
    crash_copy(&header, record, sizeof(header));
    if (header.state != RIN_CRASH_RECORD_DRAFT ||
        header.total_size < sizeof(header) ||
        header.total_size > capacity) {
        return RIN_CRASH_RECORD_STATE_ERROR;
    }
    draft_header = header;
    header.state = RIN_CRASH_RECORD_COMMITTED;
    header.payload_crc32 = crash_crc32(
        (const uint8_t*)record + sizeof(header),
        header.total_size - sizeof(header));
    header.header_crc32 = crash_header_crc(&header);
    crash_copy(record, &header, sizeof(header));
    result = rin_crash_record_validate(record, header.total_size, 1);
    if (result != RIN_CRASH_RECORD_OK) {
        crash_copy(record, &draft_header, sizeof(draft_header));
    }
    return result;
}

RinCrashRecordResult rin_crash_record_validate(
    const void* record, uint32_t available_size, int require_committed)
{
    RinCrashRecordHeader header_value;
    const RinCrashRecordHeader* header = &header_value;
    uint32_t offset;
    uint32_t index;
    uint32_t seen_sections = 0u;
    if (!record || available_size < sizeof(*header) ||
        available_size > RIN_CRASH_RECORD_MAX_SIZE) {
        return RIN_CRASH_RECORD_CORRUPT;
    }
    crash_copy(&header_value, record, sizeof(header_value));
    if (
        header->magic != RIN_CRASH_RECORD_MAGIC ||
        header->version != RIN_CRASH_RECORD_VERSION ||
        header->header_size != sizeof(*header) ||
        header->total_size < sizeof(*header) ||
        header->total_size > available_size ||
        header->section_count > RIN_CRASH_RECORD_MAX_SECTIONS ||
        !crash_kind_valid(header->kind) ||
        (header->architecture != RIN_CRASH_ARCH_X86_64 &&
         header->architecture != RIN_CRASH_ARCH_X86_32) ||
        (header->flags & ~RIN_CRASH_RECORD_FLAG_MASK) != 0u ||
        (header->flags & RIN_CRASH_RECORD_FLAG_LOCAL_ONLY) == 0u ||
        (header->kind == RIN_CRASH_RECORD_KERNEL_PANIC &&
         (header->flags & RIN_CRASH_RECORD_FLAG_USER_MODE) != 0u) ||
        (header->kind == RIN_CRASH_RECORD_USER_MINIDUMP &&
         (header->flags & RIN_CRASH_RECORD_FLAG_USER_MODE) == 0u) ||
        header->reserved != 0u ||
        (header->state != RIN_CRASH_RECORD_PREPARED &&
         header->state != RIN_CRASH_RECORD_COMMITTED) ||
        (require_committed && header->state != RIN_CRASH_RECORD_COMMITTED) ||
        header->header_crc32 != crash_header_crc(header) ||
        header->payload_crc32 != crash_crc32(
            (const uint8_t*)record + sizeof(*header),
            header->total_size - sizeof(*header))) {
        return RIN_CRASH_RECORD_CORRUPT;
    }
    offset = sizeof(*header);
    for (index = 0u; index < header->section_count; ++index) {
        RinCrashSectionHeader section_value;
        const RinCrashSectionHeader* section = &section_value;
        const uint8_t* section_data;
        uint32_t padded_size;
        uint32_t padding;
        if (offset > header->total_size ||
            sizeof(RinCrashSectionHeader) > header->total_size - offset) {
            return RIN_CRASH_RECORD_CORRUPT;
        }
        crash_copy(&section_value, (const uint8_t*)record + offset,
                   sizeof(section_value));
        section_data = (const uint8_t*)record + offset + sizeof(*section);
        if ((header->architecture == RIN_CRASH_ARCH_X86_64 &&
             section->type == RIN_CRASH_SECTION_REGISTERS_X86) ||
            (header->architecture == RIN_CRASH_ARCH_X86_32 &&
             section->type == RIN_CRASH_SECTION_REGISTERS_X64)) {
            return RIN_CRASH_RECORD_CORRUPT;
        }
        if (section->flags != 0u || section->reserved != 0u ||
            !crash_section_size_valid(section->type, section->size) ||
            (seen_sections & (UINT32_C(1) << section->type)) != 0u) {
            return RIN_CRASH_RECORD_CORRUPT;
        }
        seen_sections |= UINT32_C(1) << section->type;
        padded_size = (section->size + 7u) & ~UINT32_C(7);
        if (padded_size > header->total_size - offset - sizeof(*section)) {
            return RIN_CRASH_RECORD_CORRUPT;
        }
        if (!crash_section_content_valid(section->type, section_data,
                                         section->size)) {
            return RIN_CRASH_RECORD_CORRUPT;
        }
        for (padding = section->size; padding < padded_size; ++padding) {
            if (section_data[padding] != 0u)
                return RIN_CRASH_RECORD_CORRUPT;
        }
        offset += sizeof(*section) + padded_size;
    }
    if (offset != header->total_size ||
        (seen_sections & (UINT32_C(1) << RIN_CRASH_SECTION_MESSAGE)) == 0u ||
        (header->architecture == RIN_CRASH_ARCH_X86_64 &&
         (seen_sections &
            (UINT32_C(1) << RIN_CRASH_SECTION_REGISTERS_X64)) == 0u) ||
        (header->architecture == RIN_CRASH_ARCH_X86_32 &&
         (seen_sections &
            (UINT32_C(1) << RIN_CRASH_SECTION_REGISTERS_X86)) == 0u) ||
        (header->kind == RIN_CRASH_RECORD_USER_MINIDUMP &&
         (seen_sections & (UINT32_C(1) << RIN_CRASH_SECTION_PROCESS)) == 0u)) {
        return RIN_CRASH_RECORD_CORRUPT;
    }
    return RIN_CRASH_RECORD_OK;
}
