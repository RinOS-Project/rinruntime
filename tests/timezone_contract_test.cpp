/* SPDX-License-Identifier: MIT */

#include <cassert>
#include <cstdint>
#include <limits>

#include "../include/rinruntime/timezone.hpp"

int main() {
    using RinRuntime::ClockReading;
    using RinRuntime::TimeZoneSnapshot;
    using RinRuntime::TimeZoneTransition;

    ClockReading clock;
    clock.wallClockNanoseconds = 999999999u;
    clock.generation = 1u;
    assert(clock.valid());
    clock.wallClockNanoseconds = 1000000000u;
    assert(!clock.valid());

    TimeZoneSnapshot snapshot;
    snapshot.id = "America/Test";
    snapshot.initialOffsetSeconds = -5 * 60 * 60;
    snapshot.initialAbbreviation = "TST";
    snapshot.generation = 4u;
    snapshot.transitions.push_back(
        TimeZoneTransition{1000, -4 * 60 * 60, true, "TDT"});
    assert(snapshot.valid());

    std::int32_t offset = 0;
    bool daylight = false;
    std::string abbreviation;
    assert(snapshot.offsetAt(999, offset, daylight, abbreviation));
    assert(offset == -5 * 60 * 60 && !daylight && abbreviation == "TST");
    assert(snapshot.offsetAt(1000, offset, daylight, abbreviation));
    assert(offset == -4 * 60 * 60 && daylight && abbreviation == "TDT");

    std::int64_t local = 0;
    assert(snapshot.toLocalEpochSeconds(1000, local, offset, daylight));
    assert(local == -13400 && offset == -4 * 60 * 60 && daylight);

    TimeZoneSnapshot invalid = snapshot;
    invalid.transitions.push_back(
        TimeZoneTransition{999, -5 * 60 * 60, false, "TST"});
    assert(!invalid.valid());
    invalid = snapshot;
    invalid.id = "../escape";
    assert(!invalid.valid());
    invalid = snapshot;
    invalid.generation = 0u;
    assert(!invalid.valid());

    TimeZoneSnapshot overflow = snapshot;
    overflow.transitions.clear();
    overflow.initialOffsetSeconds = 0;
    assert(overflow.toLocalEpochSeconds(
        std::numeric_limits<std::int64_t>::max(), local, offset, daylight));
    assert(local == std::numeric_limits<std::int64_t>::max());
    overflow.initialOffsetSeconds = 60;
    assert(!overflow.toLocalEpochSeconds(
        std::numeric_limits<std::int64_t>::max(), local, offset, daylight));
    return 0;
}
