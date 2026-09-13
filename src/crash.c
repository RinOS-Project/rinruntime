/* SPDX-License-Identifier: MIT */
#include <rinruntime/crash.h>

#include <stddef.h>

int rinruntime_crash_summary_validate(
    const RinRuntimeCrashSummaryV1* summary)
{
    size_t index;
    int digest_nonzero = 0;
    if (summary == 0 || summary->struct_size != sizeof(*summary) ||
        summary->version != RINRUNTIME_CRASH_API_VERSION ||
        (summary->kind != RINRUNTIME_CRASH_USER_FAILURE &&
         summary->kind != RINRUNTIME_CRASH_RECOVERY_AVAILABLE) ||
        summary->flags != 0u || summary->message_size >= sizeof(summary->message) ||
        summary->message[summary->message_size] != '\0' ||
        summary->reserved[0] != 0u || summary->reserved[1] != 0u)
        return 0;
    for (index = 0u; index < summary->message_size; ++index) {
        const unsigned char byte = (unsigned char)summary->message[index];
        if (byte < 0x20u || byte == 0x7fu) return 0;
    }
    for (index = 0u; index < sizeof(summary->package_digest); ++index)
        digest_nonzero |= summary->package_digest[index] != 0u;
    return summary->package_generation != 0u ? digest_nonzero : !digest_nonzero;
}
