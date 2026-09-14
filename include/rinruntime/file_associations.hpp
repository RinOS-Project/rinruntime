/* SPDX-License-Identifier: MIT */
/* Bounded, user-owned default application association model. */

#ifndef RINRUNTIME_FILE_ASSOCIATIONS_HPP
#define RINRUNTIME_FILE_ASSOCIATIONS_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include <rinpath/path.h>

namespace RinRuntime {

struct FileAssociation {
    std::string extension;
    std::string application;
};

class FileAssociationService {
public:
    static constexpr std::size_t kMaxAssociations = 64u;
    static constexpr std::size_t kMaxExtensionBytes = 32u;
    static constexpr std::size_t kMaxApplicationBytes = 128u;
    static constexpr std::size_t kMaxSerializedBytes = 8192u;

private:
    std::vector<FileAssociation> entries_;

    static bool extensionValid(const std::string& value) {
        if (value.empty() || value.size() >= kMaxExtensionBytes) return false;
        for (unsigned char byte : value) {
            if (!((byte >= 'a' && byte <= 'z') ||
                  (byte >= '0' && byte <= '9') || byte == '+' ||
                  byte == '-' || byte == '_'))
                return false;
        }
        return true;
    }

    static bool applicationValid(const std::string& value) {
        if (value.empty() || value.size() >= kMaxApplicationBytes ||
            value.front() != '/' || value.compare(0u, 6u, "/apps/") != 0)
            return false;
        if (value.find("//") != std::string::npos ||
            value.find("/./") != std::string::npos ||
            value.find("/../") != std::string::npos || value == "/apps/" ||
            value.back() == '/' || value.find('\\') != std::string::npos)
            return false;
        for (unsigned char byte : value) {
            if (byte < 0x20u || byte == 0x7fu || byte == '\0') return false;
        }
        return true;
    }

    static std::string normalizeExtension(const std::string& value) {
        std::string normalized = value;
        if (!normalized.empty() && normalized.front() == '.')
            normalized.erase(0u, 1u);
        for (char& character : normalized) {
            if (character >= 'A' && character <= 'Z')
                character = static_cast<char>(character - 'A' + 'a');
        }
        return normalized;
    }

    static std::string extensionForPath(const std::string& path) {
        char extension[kMaxExtensionBytes] = {};
        std::size_t required = 0u;
        if (rin_path_extension(path.data(), path.size(), extension,
                               sizeof(extension), &required) != RIN_PATH_OK)
            return {};
        return normalizeExtension(std::string(extension, required));
    }

public:
    bool setDefault(const std::string& extension,
                    const std::string& application) {
        const std::string key = normalizeExtension(extension);
        if (!extensionValid(key) || !applicationValid(application)) return false;
        for (FileAssociation& entry : entries_) {
            if (entry.extension == key) {
                entry.application = application;
                return true;
            }
        }
        if (entries_.size() >= kMaxAssociations) return false;
        entries_.push_back({key, application});
        return true;
    }

    bool clearDefault(const std::string& extension) {
        const std::string key = normalizeExtension(extension);
        if (!extensionValid(key)) return false;
        for (auto iterator = entries_.begin(); iterator != entries_.end(); ++iterator) {
            if (iterator->extension == key) {
                entries_.erase(iterator);
                return true;
            }
        }
        return false;
    }

    const std::string* applicationForPath(const std::string& path) const {
        const std::string key = extensionForPath(path);
        if (!extensionValid(key)) return nullptr;
        for (const FileAssociation& entry : entries_)
            if (entry.extension == key) return &entry.application;
        return nullptr;
    }

    /* Resolve a user override first, then the signed-in desktop defaults.
     * Unknown extensions intentionally remain unresolved. */
    std::string applicationForPathWithDefaults(const std::string& path) const {
        if (const std::string* configured = applicationForPath(path))
            return *configured;
        const std::string key = extensionForPath(path);
        if (!extensionValid(key)) return {};
        if (key == "txt" || key == "md" || key == "log" || key == "ini" ||
            key == "conf" || key == "cfg" || key == "csv" || key == "json" ||
            key == "xml" || key == "html" || key == "htm" || key == "css" ||
            key == "js" || key == "ts" || key == "c" || key == "h" ||
            key == "cpp" || key == "hpp" || key == "py" || key == "sh")
            return "/apps/notepad/NOTEPAD.RIN";
        if (key == "mp3" || key == "flac" || key == "ogg" || key == "opus" ||
            key == "aac" || key == "m4a" || key == "wav")
            return "/apps/music/RINMUSIC.RIN";
        return {};
    }

    const std::vector<FileAssociation>& entries() const { return entries_; }

    bool encode(std::string& output) const {
        output = "RIN-FILE-ASSOCIATIONS-V1\n";
        for (const FileAssociation& entry : entries_) {
            output += entry.extension;
            output += '\t';
            output += entry.application;
            output += '\n';
            if (output.size() > kMaxSerializedBytes) {
                output.clear();
                return false;
            }
        }
        return true;
    }

    bool decode(const std::uint8_t* bytes, std::size_t size) {
        if (!bytes || size == 0u || size > kMaxSerializedBytes) return false;
        std::string text(reinterpret_cast<const char*>(bytes), size);
        if (text.compare(0u, 25u, "RIN-FILE-ASSOCIATIONS-V1\n") != 0)
            return false;
        FileAssociationService candidate;
        std::size_t cursor = 25u;
        while (cursor < text.size()) {
            const std::size_t end = text.find('\n', cursor);
            if (end == std::string::npos || end == cursor) return false;
            const std::string line = text.substr(cursor, end - cursor);
            const std::size_t tab = line.find('\t');
            if (tab == std::string::npos ||
                line.find('\t', tab + 1u) != std::string::npos)
                return false;
            if (!candidate.setDefault(line.substr(0u, tab),
                                      line.substr(tab + 1u)))
                return false;
            cursor = end + 1u;
        }
        entries_.swap(candidate.entries_);
        return true;
    }
};

} // namespace RinRuntime

#endif /* RINRUNTIME_FILE_ASSOCIATIONS_HPP */
