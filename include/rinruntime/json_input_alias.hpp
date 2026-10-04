/* SPDX-License-Identifier: MIT */
/* Internal failure-atomicity helpers for public JSON adapters. */
#ifndef RINRUNTIME_JSON_INPUT_ALIAS_HPP
#define RINRUNTIME_JSON_INPUT_ALIAS_HPP

#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace RinRuntime {
namespace detail {

inline bool jsonStorageRangesOverlap(const void* first,
                                     std::size_t firstSize,
                                     const void* second,
                                     std::size_t secondSize) {
    if (first == nullptr || second == nullptr || firstSize == 0u ||
        secondSize == 0u)
        return false;
    const std::uintptr_t firstBegin =
        reinterpret_cast<std::uintptr_t>(first);
    const std::uintptr_t secondBegin =
        reinterpret_cast<std::uintptr_t>(second);
    const std::uintptr_t maximum =
        std::numeric_limits<std::uintptr_t>::max();
    if (firstBegin > maximum - firstSize ||
        secondBegin > maximum - secondSize)
        return true;
    return firstBegin < secondBegin + secondSize &&
           secondBegin < firstBegin + firstSize;
}

inline bool jsonInputOverlaps(std::string_view input, const void* storage,
                              std::size_t storageSize) {
    return jsonStorageRangesOverlap(input.data(), input.size(), storage,
                                    storageSize);
}

inline bool jsonStorageOverlaps(const void* storage, std::size_t storageSize,
                                const std::string& value) {
    return !value.empty() &&
           jsonStorageRangesOverlap(storage, storageSize, value.data(),
                                    value.capacity());
}

inline bool jsonInputOverlaps(std::string_view input,
                              const std::string& value) {
    return jsonInputOverlaps(input, value.data(), value.capacity());
}

template <typename T>
inline bool jsonStorageOverlaps(const void* storage, std::size_t storageSize,
                                const std::vector<T>& values) {
    if (values.empty()) return false;
    if (values.size() >
        std::numeric_limits<std::size_t>::max() / sizeof(T))
        return true;
    return jsonStorageRangesOverlap(storage, storageSize, values.data(),
                                    values.size() * sizeof(T));
}

template <typename T>
inline bool jsonInputOverlaps(std::string_view input,
                              const std::vector<T>& values) {
    if (values.empty()) return false;
    if (values.size() >
        std::numeric_limits<std::size_t>::max() / sizeof(T))
        return true;
    return jsonInputOverlaps(input, values.data(),
                             values.size() * sizeof(T));
}

} // namespace detail
} // namespace RinRuntime

#endif /* RINRUNTIME_JSON_INPUT_ALIAS_HPP */
