/* SPDX-License-Identifier: MIT */
/* Bounded, renderer-independent setting metadata search model. */

#ifndef RINRUNTIME_SETTINGS_SEARCH_HPP
#define RINRUNTIME_SETTINGS_SEARCH_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "cancellation.h"
#include "text_input.hpp"

namespace RinRuntime {

struct SettingSearchMetadata {
    std::string id;
    std::string title;
    std::string keywords;
    std::string category;
};

class SettingSearchIndex {
    static constexpr std::size_t kMaximumEntries = 256u;
    static constexpr std::size_t kMaximumFieldBytes = 255u;
    static constexpr std::size_t kMaximumQueryBytes = 128u;

    std::vector<SettingSearchMetadata> entries_;
    std::string query_;

    static bool validText(const std::string& value, bool allowEmpty) {
        if (!allowEmpty && value.empty()) return false;
        if (value.length() > kMaximumFieldBytes) return false;
        for (size_t index = 0u; index < value.length(); ++index) {
            const unsigned char byte =
                static_cast<unsigned char>(value[index]);
            if (byte == 0u || byte < 0x20u || byte == 0x7fu) return false;
        }
        TextInputModel validator;
        return validator.setText(value);
    }

    static unsigned char foldAscii(unsigned char value) {
        return value >= static_cast<unsigned char>('A') &&
                       value <= static_cast<unsigned char>('Z')
                   ? static_cast<unsigned char>(value + ('a' - 'A'))
                   : value;
    }

    static bool containsFolded(const std::string& haystack,
                               const std::string& needle) {
        if (needle.empty()) return true;
        if (needle.length() > haystack.length()) return false;
        for (size_t start = 0u;
             start + needle.length() <= haystack.length(); ++start) {
            bool equal = true;
            for (size_t offset = 0u; offset < needle.length(); ++offset) {
                if (foldAscii(static_cast<unsigned char>(haystack[start + offset])) !=
                    foldAscii(static_cast<unsigned char>(needle[offset]))) {
                    equal = false;
                    break;
                }
            }
            if (equal) return true;
        }
        return false;
    }

    static bool containsToken(const SettingSearchMetadata& entry,
                              const std::string& token) {
        return containsFolded(entry.id, token) ||
               containsFolded(entry.title, token) ||
               containsFolded(entry.keywords, token) ||
               containsFolded(entry.category, token);
    }

public:
    enum class MatchResult : std::uint8_t {
        Completed = 0,
        Cancelled = 1,
        InvalidArgument = 2,
    };

    static constexpr size_t maximumEntries() { return kMaximumEntries; }
    static constexpr size_t maximumQueryBytes() { return kMaximumQueryBytes; }

    void clear() {
        entries_.clear();
        query_.clear();
    }

    bool add(const SettingSearchMetadata& metadata) {
        if (entries_.size() >= kMaximumEntries ||
            !validText(metadata.id, false) ||
            !validText(metadata.title, false) ||
            !validText(metadata.keywords, true) ||
            !validText(metadata.category, true))
            return false;
        for (const auto& entry : entries_)
            if (entry.id == metadata.id) return false;
        entries_.push_back(metadata);
        return true;
    }

    bool setQuery(const std::string& value) {
        if (value.length() > kMaximumQueryBytes || !validText(value, true))
            return false;
        query_ = value;
        return true;
    }

    const std::string& query() const { return query_; }
    size_t size() const { return entries_.size(); }

    const SettingSearchMetadata* entry(size_t index) const {
        return index < entries_.size() ? &entries_[index] : nullptr;
    }

    bool matches(size_t index) const {
        const SettingSearchMetadata* metadata = entry(index);
        if (!metadata) return false;
        if (query_.empty()) return true;
        size_t tokenStart = 0u;
        while (tokenStart < query_.length()) {
            while (tokenStart < query_.length() &&
                   query_[tokenStart] == ' ')
                ++tokenStart;
            if (tokenStart == query_.length()) break;
            size_t tokenEnd = tokenStart;
            while (tokenEnd < query_.length() && query_[tokenEnd] != ' ')
                ++tokenEnd;
            if (!containsToken(*metadata,
                               query_.substr(tokenStart, tokenEnd - tokenStart)))
                return false;
            tokenStart = tokenEnd;
        }
        return true;
    }

    MatchResult matchingIndicesCancellable(
        size_t* output, size_t capacity,
        RinRuntimeCancellationFunction cancellation, void* context,
        size_t* matchedCount) const {
        if (matchedCount == nullptr || (!output && capacity != 0u))
            return MatchResult::InvalidArgument;
        *matchedCount = 0u;
        for (size_t index = 0u; index < entries_.size(); ++index) {
            if (cancellation != nullptr && cancellation(context) != 0) {
                for (size_t clear = 0u; clear < *matchedCount && clear < capacity;
                     ++clear)
                    output[clear] = 0u;
                *matchedCount = 0u;
                return MatchResult::Cancelled;
            }
            if (!matches(index)) continue;
            if (*matchedCount < capacity) output[*matchedCount] = index;
            ++*matchedCount;
        }
        return MatchResult::Completed;
    }

    size_t matchingIndices(size_t* output, size_t capacity) const {
        size_t count = 0u;
        if (matchingIndicesCancellable(output, capacity, nullptr, nullptr,
                                       &count) != MatchResult::Completed)
            return 0u;
        return count;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_SETTINGS_SEARCH_HPP */
