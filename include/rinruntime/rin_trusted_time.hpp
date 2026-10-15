/* SPDX-License-Identifier: MIT */
#ifndef RIN_SHARED_TRUSTED_TIME_HPP
#define RIN_SHARED_TRUSTED_TIME_HPP

#include <cstdint>
#include <limits>
#include <time.h>

/* CLOCK_REALTIME is backed by the RinOS realtime owner on product builds.
 * Never substitute the legacy SYS_TIME tick counter or ambient host time. */
inline bool rin_shared_trusted_realtime_ns(std::uint64_t& unixTimeNs)
{
    unixTimeNs = 0u;
    timespec snapshot{};
    if (clock_gettime(CLOCK_REALTIME, &snapshot) != 0 ||
        snapshot.tv_sec <= 0 || snapshot.tv_nsec < 0 ||
        snapshot.tv_nsec >= 1000000000L)
        return false;

    const std::uint64_t seconds = static_cast<std::uint64_t>(snapshot.tv_sec);
    constexpr std::uint64_t kMaximumUnixSeconds = UINT64_C(253402300799);
    constexpr std::uint64_t kNanosecondsPerSecond = UINT64_C(1000000000);
    if (seconds > kMaximumUnixSeconds ||
        seconds > (std::numeric_limits<std::uint64_t>::max() -
                   static_cast<std::uint64_t>(snapshot.tv_nsec)) /
                      kNanosecondsPerSecond)
        return false;

    unixTimeNs = seconds * kNanosecondsPerSecond +
                 static_cast<std::uint64_t>(snapshot.tv_nsec);
    return unixTimeNs != 0u;
}

inline bool rin_shared_trusted_unix_seconds(std::uint64_t& unixTime)
{
    std::uint64_t unixTimeNs = 0u;
    if (!rin_shared_trusted_realtime_ns(unixTimeNs)) {
        unixTime = 0u;
        return false;
    }
    unixTime = unixTimeNs / UINT64_C(1000000000);
    return unixTime != 0u;
}

#endif /* RIN_SHARED_TRUSTED_TIME_HPP */
