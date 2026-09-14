/* SPDX-License-Identifier: MIT */
/* Backend-independent application metadata for public consumers. */
#ifndef RINRUNTIME_APPLICATION_METADATA_HPP
#define RINRUNTIME_APPLICATION_METADATA_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace RinRuntime {

static constexpr std::size_t kApplicationMetadataMaxIdBytes = 63u;
static constexpr std::size_t kApplicationMetadataMaxNameBytes = 127u;
static constexpr std::size_t kApplicationMetadataMaxEntryPointBytes = 191u;
static constexpr std::size_t kApplicationMetadataMaxIconIdBytes = 127u;
static constexpr std::size_t kApplicationMetadataMaxDescriptionBytes = 255u;
static constexpr std::size_t kApplicationMetadataMaxTags = 16u;

struct ApplicationMetadata {
    std::string applicationId;
    std::string displayName;
    std::string entryPoint;
    std::string iconId;
    std::string description;
    std::vector<std::string> categories;
    std::vector<std::string> mimeTypes;
    bool gui = false;

    static bool validIdentifier(const std::string& value,
                                std::size_t maximum) {
        if (value.empty() || value.size() > maximum) return false;
        for (const unsigned char byte : value) {
            if (byte < 0x21u || byte == 0x7fu || byte == '/' ||
                byte == '\\' || byte == ':')
                return false;
        }
        return true;
    }

    static bool validText(const std::string& value, std::size_t maximum,
                          bool allowEmpty) {
        if (value.size() > maximum || (!allowEmpty && value.empty()))
            return false;
        for (const unsigned char byte : value)
            if (byte < 0x20u || byte == 0x7fu) return false;
        return true;
    }

    static bool validRelativePath(const std::string& value) {
        if (value.empty() || value.size() > kApplicationMetadataMaxEntryPointBytes ||
            value.front() == '/' || value.back() == '/')
            return false;
        std::size_t start = 0u;
        while (start < value.size()) {
            std::size_t end = value.find('/', start);
            if (end == std::string::npos) end = value.size();
            if (end == start || value.substr(start, end - start) == "." ||
                value.substr(start, end - start) == "..")
                return false;
            for (std::size_t index = start; index < end; ++index) {
                const unsigned char byte =
                    static_cast<unsigned char>(value[index]);
                if (byte < 0x20u || byte == 0x7fu || byte == '\\' ||
                    byte == ':')
                    return false;
            }
            if (end == value.size()) break;
            start = end + 1u;
        }
        return true;
    }

    static bool sortedUniqueTags(const std::vector<std::string>& values) {
        for (std::size_t index = 0u; index < values.size(); ++index) {
            if (!validIdentifier(values[index], kApplicationMetadataMaxIdBytes) ||
                (index != 0u && values[index - 1u] >= values[index]))
                return false;
        }
        return true;
    }

    static bool validMimeType(const std::string& value) {
        if (value.empty() || value.size() > kApplicationMetadataMaxIconIdBytes)
            return false;
        const std::size_t slash = value.find('/');
        if (slash == 0u || slash == value.size() - 1u ||
            value.find('/', slash + 1u) != std::string::npos)
            return false;
        for (const unsigned char byte : value) {
            if (byte < 0x21u || byte == 0x7fu || byte == '\\' ||
                byte == ':')
                return false;
        }
        return true;
    }

    static bool sortedUniqueMimeTypes(const std::vector<std::string>& values) {
        for (std::size_t index = 0u; index < values.size(); ++index) {
            if (!validMimeType(values[index]) ||
                (index != 0u && values[index - 1u] >= values[index]))
                return false;
        }
        return true;
    }

    bool valid() const {
        return validIdentifier(applicationId, kApplicationMetadataMaxIdBytes) &&
               validText(displayName, kApplicationMetadataMaxNameBytes, false) &&
               validRelativePath(entryPoint) &&
               (iconId.empty() ||
                validIdentifier(iconId, kApplicationMetadataMaxIconIdBytes)) &&
               validText(description, kApplicationMetadataMaxDescriptionBytes, true) &&
               categories.size() <= kApplicationMetadataMaxTags &&
               mimeTypes.size() <= kApplicationMetadataMaxTags &&
               sortedUniqueTags(categories) && sortedUniqueMimeTypes(mimeTypes);
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_APPLICATION_METADATA_HPP */
