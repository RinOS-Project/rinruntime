/* SPDX-License-Identifier: MIT */

#include <rin/crash_summary.h>
#include <rin/contract_abi.h>

#include <stddef.h>

#if !defined(_WIN32)
#include "../../libc/sys/syscall.h"
#include <rin/syscall_abi.h>
#endif

static void summary_zero(void* output, uint32_t size)
{
    uint8_t* bytes = (uint8_t*)output;
    uint32_t index;
    for (index = 0u; index < size; ++index) bytes[index] = 0u;
}

static void summary_copy(void* output, const void* input, uint32_t size)
{
    uint8_t* destination = (uint8_t*)output;
    const uint8_t* source = (const uint8_t*)input;
    uint32_t index;
    for (index = 0u; index < size; ++index) destination[index] = source[index];
}

RinCrashRecordResult rin_crash_summary_decode(
    const void* record, uint32_t record_size, RinCrashSummaryV1* summary)
{
    RinCrashRecordHeader header;
    uint32_t offset;
    uint32_t index;
    if (!record || !summary ||
        rin_crash_record_validate(record, record_size, 1) !=
            RIN_CRASH_RECORD_OK) {
        return RIN_CRASH_RECORD_CORRUPT;
    }
    summary_copy(&header, record, sizeof(header));
    summary_zero(summary, sizeof(*summary));
    summary->struct_size = sizeof(*summary);
    summary->version = RIN_CRASH_SUMMARY_VERSION;
    summary->disclosure_policy = RIN_CRASH_SUMMARY_POLICY_LOCAL_ONLY;
    summary->kind = header.kind;
    summary->architecture = header.architecture;
    summary->process_id = header.process_id;
    summary->thread_id = header.thread_id;
    summary->exception_code = header.exception_code;
    summary->sequence = header.sequence;
    summary->timestamp_ns = header.timestamp_ns;
    summary->boot_id_high = header.boot_id_high;
    summary->boot_id_low = header.boot_id_low;

    offset = sizeof(header);
    for (index = 0u; index < header.section_count; ++index) {
        RinCrashSectionHeader section;
        const uint8_t* data;
        uint32_t padded_size;
        summary_copy(&section, (const uint8_t*)record + offset,
                     sizeof(section));
        data = (const uint8_t*)record + offset + sizeof(section);
        padded_size = (section.size + 7u) & ~UINT32_C(7);
        switch (section.type) {
            case RIN_CRASH_SECTION_MESSAGE:
                summary_copy(summary->message, data, section.size);
                summary->message[section.size] = '\0';
                summary->message_size = section.size;
                break;
            case RIN_CRASH_SECTION_REGISTERS_X64:
                /* Copy only control-flow fields; older records can contain
                 * secret fragments in any other saved register. */
                summary_copy(
                    &summary->registers.gpr[RIN_CRASH_X64_RSP],
                    data + offsetof(RinCrashRegistersX64, gpr) +
                        RIN_CRASH_X64_RSP * sizeof(uint64_t),
                    sizeof(uint64_t));
                summary_copy(
                    &summary->registers.rip,
                    data + offsetof(RinCrashRegistersX64, rip),
                    sizeof(summary->registers.rip));
                summary_copy(
                    &summary->registers.rflags,
                    data + offsetof(RinCrashRegistersX64, rflags),
                    sizeof(summary->registers.rflags));
                summary_copy(
                    &summary->registers.cr2,
                    data + offsetof(RinCrashRegistersX64, cr2),
                    sizeof(summary->registers.cr2));
                break;
            case RIN_CRASH_SECTION_REGISTERS_X86: {
                summary_copy(
                    &summary->registers.gpr[RIN_CRASH_X64_RSP],
                    data + offsetof(RinCrashRegistersX86, gpr) +
                        RIN_CRASH_X86_ESP * sizeof(uint32_t),
                    sizeof(uint32_t));
                summary_copy(
                    &summary->registers.rip,
                    data + offsetof(RinCrashRegistersX86, eip),
                    sizeof(uint32_t));
                summary_copy(
                    &summary->registers.rflags,
                    data + offsetof(RinCrashRegistersX86, eflags),
                    sizeof(uint32_t));
                summary_copy(
                    &summary->registers.cr2,
                    data + offsetof(RinCrashRegistersX86, cr2),
                    sizeof(uint32_t));
                break;
            }
            case RIN_CRASH_SECTION_STACKTRACE_X64:
                summary->stack_frame_count =
                    section.size / (uint32_t)sizeof(uint64_t);
                summary_copy(summary->stack_frames, data, section.size);
                break;
            case RIN_CRASH_SECTION_PROCESS:
                summary_copy(&summary->process, data, section.size);
                summary->has_process = 1u;
                break;
            case RIN_CRASH_SECTION_SCHEDULER:
                summary_copy(&summary->scheduler, data,
                             sizeof(summary->scheduler));
                summary->has_scheduler = 1u;
                break;
            default:
                return RIN_CRASH_RECORD_CORRUPT;
        }
        offset += sizeof(section) + padded_size;
    }
    return RIN_CRASH_RECORD_OK;
}

int rin_crash_summary_get_local(RinCrashSummaryV1* summary)
{
    if (summary == NULL) return (int)RIN_RESULT_INVALID_ARGUMENT;
    summary_zero(summary, (uint32_t)sizeof(*summary));
#if defined(_WIN32)
    return (int)RIN_RESULT_NOT_SUPPORTED;
#else
    return (int)_syscall2((uintptr_t)RIN_SYS_CRASH_SUMMARY_GET,
                          (uintptr_t)summary,
                          (uintptr_t)sizeof(*summary));
#endif
}

int rin_crash_history_get_local(RinCrashHistoryQueryV1* query)
{
    if (query == NULL) return (int)RIN_RESULT_INVALID_ARGUMENT;
    query->record_count = 0u;
    summary_zero(query->records, (uint32_t)sizeof(query->records));
#if defined(_WIN32)
    return (int)RIN_RESULT_NOT_SUPPORTED;
#else
    intptr_t result;
    result = _syscall2((uintptr_t)RIN_SYS_CRASH_SUMMARY_GET,
                       (uintptr_t)query,
                       (uintptr_t)sizeof(*query));
    if (result != (intptr_t)RIN_RESULT_OK) {
        query->record_count = 0u;
        summary_zero(query->records, (uint32_t)sizeof(query->records));
    }
    return (int)result;
#endif
}

int rin_crash_history_ack_local(uint64_t sequence)
{
    RinCrashHistoryAckV1 ack;
    intptr_t result;
    summary_zero(&ack, (uint32_t)sizeof(ack));
    ack.struct_size = (uint32_t)sizeof(ack);
    ack.version = RIN_CRASH_HISTORY_ACK_VERSION;
    ack.sequence = sequence;
#if defined(_WIN32)
    result = (intptr_t)RIN_RESULT_NOT_SUPPORTED;
#else
    result = _syscall2((uintptr_t)RIN_SYS_CRASH_SUMMARY_GET,
                       (uintptr_t)&ack, (uintptr_t)sizeof(ack));
#endif
    summary_zero(&ack, (uint32_t)sizeof(ack));
    return (int)result;
}
