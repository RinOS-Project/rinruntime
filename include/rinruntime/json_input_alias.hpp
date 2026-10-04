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

inline bool jsonInputOverlaps(std::string_view input, const void* storage,
                              std::size_t storageSize) {
    if (input.empty() || storage == nullptr || storageSize == 0u)
        return false;
    const std::uintptr_t inputBegin =
        reinterpret_cast<std::uintptr_t>(input.data());
    const std::uintptr_t storageBegin =
        reinterpret_cast<std::uintptr_t>(storage);
    const std::uintptr_t maximum =
        std::numeric_limits<std::uintptr_t>::max();
    if (inputBegin > maximum - input.size() ||
        storageBegin > maximum - storageSize)
        return true;
    return inputBegin < storageBegin + storageSize &&
           storageBegin < inputBegin + input.size();
}

inline bool jsonInputOverlaps(std::string_view input,
                              const std::string& value) {
    return !value.empty() &&
           jsonInputOverlaps(input, value.data(), value.capacity());
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
