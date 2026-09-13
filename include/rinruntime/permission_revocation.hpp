/* SPDX-License-Identifier: MIT */
/* Backend-independent permission revocation event and cursor model. */

#ifndef RINRUNTIME_PERMISSION_REVOCATION_HPP
#define RINRUNTIME_PERMISSION_REVOCATION_HPP

#include <cstddef>
#include <cstdint>
#include <string>

namespace RinRuntime {

/* A revocation is emitted by the trusted permission owner.  The event has no
 * renderer-owned capability or payload; it only identifies the profile/site
 * bucket that must be re-queried before a sensitive operation continues. */
struct PermissionRevocation {
    static constexpr std::size_t kMaxProfileIdBytes = 63u;
    static constexpr std::size_t kMaxDomainBytes = 255u;
    static constexpr std::size_t kMaxPermissionTypeBytes = 32u;

    std::uint64_t sequence = 0u;
    std::string profileId;
    std::string domain;
    std::string permissionType;

    bool valid() const {
        return sequence != 0u && validProfileId(profileId) &&
               validDomain(domain) && validPermissionType(permissionType);
    }

private:
    static bool validProfileId(const std::string& value) {
        if (value.empty() || value.size() > kMaxProfileIdBytes) return false;
        for (unsigned char byte : value) {
            const bool alpha = (byte >= static_cast<unsigned char>('a') &&
                                byte <= static_cast<unsigned char>('z')) ||
                               (byte >= static_cast<unsigned char>('A') &&
                                byte <= static_cast<unsigned char>('Z'));
            const bool digit = byte >= static_cast<unsigned char>('0') &&
                               byte <= static_cast<unsigned char>('9');
            if (!alpha && !digit && byte != static_cast<unsigned char>('_') &&
                byte != static_cast<unsigned char>('-')) return false;
        }
        return true;
    }

    static bool validDomain(const std::string& value) {
        if (value.empty() || value.size() > kMaxDomainBytes) return false;
        if (value == "*") return true;
        if (value.front() == '[') {
            if (value.size() < 4u || value.back() != ']') return false;
            bool hasColon = false;
            unsigned int groups = 0u;
            bool compressed = false;
            std::size_t index = 1u;
            while (index + 1u < value.size()) {
                if (value[index] == ':') {
                    if (index + 1u >= value.size() - 1u ||
                        value[index + 1u] != ':' || compressed)
                        return false;
                    compressed = true;
                    hasColon = true;
                    index += 2u;
                    if (index + 1u == value.size()) break;
                }
                unsigned int digits = 0u;
                while (index + 1u < value.size() && value[index] != ':') {
                    const unsigned char byte =
                        static_cast<unsigned char>(value[index]);
                    const bool hex =
                        (byte >= static_cast<unsigned char>('0') &&
                         byte <= static_cast<unsigned char>('9')) ||
                        (byte >= static_cast<unsigned char>('a') &&
                         byte <= static_cast<unsigned char>('f')) ||
                        (byte >= static_cast<unsigned char>('A') &&
                         byte <= static_cast<unsigned char>('F'));
                    if (!hex || ++digits > 4u) return false;
                    ++index;
                }
                if (digits == 0u || ++groups > 8u) return false;
                if (index + 1u == value.size()) break;
                if (value[index] != ':') return false;
                hasColon = true;
                if (index + 2u < value.size() && value[index + 1u] == ':') {
                    if (compressed) return false;
                    compressed = true;
                    index += 2u;
                } else {
                    ++index;
                    if (index + 1u == value.size()) return false;
                }
            }
            return hasColon && (compressed ? groups < 8u : groups == 8u);
        }
        if (value.front() == '.' || value.back() == '.' ||
            value.front() == '-' || value.find('[') != std::string::npos ||
            value.find(']') != std::string::npos)
            return false;
        bool labelHasCharacter = false;
        unsigned char previous = 0u;
        for (unsigned char byte : value) {
            /* The Browser normalizes a host before enqueueing an event.  The
             * public model deliberately accepts only the canonical printable
             * host key shape, never an origin, path, or control byte. */
            const bool alpha =
                (byte >= static_cast<unsigned char>('a') &&
                 byte <= static_cast<unsigned char>('z')) ||
                (byte >= static_cast<unsigned char>('A') &&
                 byte <= static_cast<unsigned char>('Z'));
            const bool digit = byte >= static_cast<unsigned char>('0') &&
                               byte <= static_cast<unsigned char>('9');
            if ((!alpha && !digit && byte != static_cast<unsigned char>('-') &&
                 byte != static_cast<unsigned char>('.')) ||
                byte < 0x21u || byte > 0x7eu) return false;
            if (byte == '.') {
                if (!labelHasCharacter || previous == '-') return false;
                labelHasCharacter = false;
            } else {
                if (byte == '-' && !labelHasCharacter) return false;
                labelHasCharacter = true;
            }
            previous = byte;
        }
        return labelHasCharacter && previous != '-';
    }

    static bool validPermissionType(const std::string& value) {
        if (value.empty() || value.size() > kMaxPermissionTypeBytes) return false;
        for (unsigned char byte : value) {
            const bool alpha = (byte >= static_cast<unsigned char>('a') &&
                                byte <= static_cast<unsigned char>('z')) ||
                               (byte >= static_cast<unsigned char>('A') &&
                                byte <= static_cast<unsigned char>('Z'));
            const bool digit = byte >= static_cast<unsigned char>('0') &&
                               byte <= static_cast<unsigned char>('9');
            if (!alpha && !digit && byte != static_cast<unsigned char>('_') &&
                byte != static_cast<unsigned char>('-')) return false;
        }
        return true;
    }
};

/* Cursor helper shared by chrome and renderer adapters.  A cursor is valid
 * only when it advances monotonically through retained events.  The caller
 * supplies the oldest retained sequence so queue eviction is detected before
 * a stale renderer can continue using a capability. */
class PermissionRevocationCursor {
public:
    static constexpr std::uint64_t kUninitialized = 0u;

    std::uint64_t value() const { return cursor_; }

    void reset(std::uint64_t value = kUninitialized) { cursor_ = value; }

    bool stale(std::uint64_t oldestRetained) const {
        if (oldestRetained == 0u || cursor_ == ~std::uint64_t(0)) return false;
        return cursor_ + 1u < oldestRetained;
    }

    bool accept(const PermissionRevocation& event,
                std::uint64_t oldestRetained) {
        if (!event.valid() || stale(oldestRetained) ||
            event.sequence <= cursor_) return false;
        cursor_ = event.sequence;
        return true;
    }

private:
    std::uint64_t cursor_ = kUninitialized;
};

} // namespace RinRuntime

#endif /* RINRUNTIME_PERMISSION_REVOCATION_HPP */
