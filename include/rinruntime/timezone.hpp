/* SPDX-License-Identifier: MIT */
/* Backend-independent bounded time and timezone snapshots. */
#ifndef RINRUNTIME_TIMEZONE_HPP
#define RINRUNTIME_TIMEZONE_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace RinRuntime {

/* A clock reading is data supplied by an OS/service owner.  The public model
 * deliberately has no syscall, RTC, timezone database, or persistence
 * dependency. */
struct ClockReading {
    std::uint64_t monotonicNanoseconds = 0u;
    std::int64_t wallClockSeconds = 0;
    std::uint32_t wallClockNanoseconds = 0u;
    std::uint64_t generation = 0u;

    bool valid() const noexcept {
        return wallClockNanoseconds < 1000000000u && generation != 0u;
    }
};

struct TimeZoneTransition {
    std::int64_t atEpochSeconds = 0;
    std::int32_t offsetSeconds = 0;
    bool daylight = false;
    std::string abbreviation;

    bool valid() const {
        return offsetSeconds >= -kMaxOffsetSeconds &&
               offsetSeconds <= kMaxOffsetSeconds &&
               (abbreviation.empty() ||
                validAbbreviation(abbreviation));
    }

private:
    static constexpr std::int32_t kMaxOffsetSeconds = 24 * 60 * 60;

    static bool validAbbreviation(const std::string& value) {
        if (value.size() > 15u) return false;
        for (const unsigned char byte : value)
            if (byte < 0x21u || byte > 0x7eu) return false;
        return true;
    }
};

/* Public consumers receive one immutable-style bounded snapshot from a
 * private timezone/service owner.  The owner may populate transitions from
 * TZif/ICU data; this model never parses that data itself. */
class TimeZoneSnapshot final {
public:
    static constexpr std::size_t kMaxIdBytes = 127u;
    static constexpr std::size_t kMaxTransitions = 256u;
    static constexpr std::int32_t kMaxOffsetSeconds = 24 * 60 * 60;

    std::string id;
    std::int32_t initialOffsetSeconds = 0;
    bool initialDaylight = false;
    std::string initialAbbreviation;
    std::vector<TimeZoneTransition> transitions;
    std::uint64_t generation = 0u;

    static bool validIdentifier(const std::string& value) {
        if (value.empty() || value.size() > kMaxIdBytes ||
            value.front() == '/' || value.back() == '/')
            return false;
        std::size_t start = 0u;
        while (start < value.size()) {
            std::size_t end = value.find('/', start);
            if (end == std::string::npos) end = value.size();
            if (end == start ||
                (end - start == 1u && value[start] == '.') ||
                (end - start == 2u && value[start] == '.' &&
                 value[start + 1u] == '.'))
                return false;
            for (std::size_t index = start; index < end; ++index) {
                const unsigned char byte =
                    static_cast<unsigned char>(value[index]);
                if (byte < 0x21u || byte > 0x7eu || byte == '\\' ||
                    byte == ':')
                    return false;
            }
            if (end == value.size()) break;
            start = end + 1u;
        }
        return true;
    }

    static bool validAbbreviation(const std::string& value) {
        if (value.size() > 15u) return false;
        for (const unsigned char byte : value)
            if (byte < 0x21u || byte > 0x7eu) return false;
        return true;
    }

    static bool validOffset(std::int32_t offset) noexcept {
        return offset >= -kMaxOffsetSeconds && offset <= kMaxOffsetSeconds;
    }

    bool valid() const {
        if (!validIdentifier(id) || !validOffset(initialOffsetSeconds) ||
            !validAbbreviation(initialAbbreviation) || generation == 0u ||
            transitions.size() > kMaxTransitions)
            return false;
        std::int64_t previous = std::numeric_limits<std::int64_t>::min();
        for (const TimeZoneTransition& transition : transitions) {
            if (!validOffset(transition.offsetSeconds) ||
                !validAbbreviation(transition.abbreviation) ||
                transition.atEpochSeconds <= previous)
                return false;
            previous = transition.atEpochSeconds;
        }
        return true;
    }

    bool offsetAt(std::int64_t epochSeconds, std::int32_t& offsetSeconds,
                  bool& daylight, std::string& abbreviation) const {
        if (!valid()) {
            offsetSeconds = 0;
            daylight = false;
            abbreviation.clear();
            return false;
        }
        offsetSeconds = initialOffsetSeconds;
        daylight = initialDaylight;
        abbreviation = initialAbbreviation;
        for (const TimeZoneTransition& transition : transitions) {
            if (transition.atEpochSeconds > epochSeconds) break;
            offsetSeconds = transition.offsetSeconds;
            daylight = transition.daylight;
            abbreviation = transition.abbreviation;
        }
        return true;
    }

    bool toLocalEpochSeconds(std::int64_t epochSeconds,
                             std::int64_t& localEpochSeconds,
                             std::int32_t& offsetSeconds,
                             bool& daylight) const {
        std::string ignoredAbbreviation;
        if (!offsetAt(epochSeconds, offsetSeconds, daylight,
                      ignoredAbbreviation)) {
            localEpochSeconds = 0;
            offsetSeconds = 0;
            daylight = false;
            return false;
        }
        const std::int64_t offset = offsetSeconds;
        if ((offset > 0 && epochSeconds >
                              std::numeric_limits<std::int64_t>::max() - offset) ||
            (offset < 0 && epochSeconds <
                              std::numeric_limits<std::int64_t>::min() - offset)) {
            localEpochSeconds = 0;
            offsetSeconds = 0;
            daylight = false;
            return false;
        }
        localEpochSeconds = epochSeconds + offset;
        return true;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_TIMEZONE_HPP */
