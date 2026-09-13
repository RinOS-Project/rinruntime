/* SPDX-License-Identifier: MIT */
#include <rinruntime/crash.h>
#include <cstring>
int main() {
    RinRuntimeCrashSummaryV1 summary = {};
    summary.struct_size = sizeof(summary);
    summary.version = RINRUNTIME_CRASH_API_VERSION;
    summary.kind = RINRUNTIME_CRASH_USER_FAILURE;
    summary.message_size = 5u;
    std::memcpy(summary.message, "error", 5u);
    return rinruntime_crash_summary_validate(&summary) ? 0 : 1;
}
