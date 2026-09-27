/* SPDX-License-Identifier: MIT */
/* Backend-independent ABI symbol lifecycle model for public consumers. */
#ifndef RINRUNTIME_ABI_SYMBOL_POLICY_HPP
#define RINRUNTIME_ABI_SYMBOL_POLICY_HPP

#include "abi_policy.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace RinRuntime {

/* This is descriptive metadata only.  SONAMEs, linker export tables,
 * symbol addresses, signatures, trust, and loader admission remain private
 * packaging/loader-owner responsibilities. */
enum class AbiSymbolState : std::uint8_t {
    Stable,
    Optional,
    Deprecated,
    Removed,
};

struct AbiSymbolLifecycle final {
    std::string name;
    AbiSymbolState state = AbiSymbolState::Stable;
    AbiVersion introduced{};
    AbiVersion deprecatedSince{};
    AbiVersion removedSince{};

    bool valid() const noexcept;
};

struct AbiSymbolPolicyManifest final {
    static constexpr std::size_t maxSymbols = 256u;
    static constexpr std::size_t maxManifestIdBytes = 63u;

    AbiVersion abiVersion{};
    std::string manifestId;
    std::vector<AbiSymbolLifecycle> symbols;

    bool valid() const noexcept;

    const AbiSymbolLifecycle* find(std::string_view symbolName) const noexcept;

    bool available(std::string_view symbolName) const noexcept {
        const auto* symbol = find(symbolName);
        return symbol != nullptr && symbol->state != AbiSymbolState::Removed;
    }

    bool deprecated(std::string_view symbolName) const noexcept {
        const auto* symbol = find(symbolName);
        return symbol != nullptr &&
               (symbol->state == AbiSymbolState::Deprecated ||
                (symbol->state == AbiSymbolState::Removed &&
                 symbol->deprecatedSince.valid()));
    }
};

namespace detail {

constexpr bool abiVersionIsZero(const AbiVersion& version) noexcept {
    return version.major == 0u && version.minor == 0u;
}

constexpr bool abiVersionAtLeast(const AbiVersion& left,
                                 const AbiVersion& right) noexcept {
    return left.valid() && right.valid() &&
           (left.major > right.major ||
            (left.major == right.major && left.minor >= right.minor));
}

inline bool visibleAsciiIdentifier(std::string_view value,
                                   std::size_t maximumBytes) noexcept {
    if (value.empty() || value.size() > maximumBytes)
        return false;
    for (const unsigned char byte : value) {
        if (byte < 0x21u || byte > 0x7eu)
            return false;
    }
    return true;
}

} // namespace detail

inline bool AbiSymbolLifecycle::valid() const noexcept {
    if (!detail::visibleAsciiIdentifier(name, 127u) || !introduced.valid())
        return false;

    switch (state) {
    case AbiSymbolState::Stable:
    case AbiSymbolState::Optional:
        return detail::abiVersionIsZero(deprecatedSince) &&
               detail::abiVersionIsZero(removedSince);
    case AbiSymbolState::Deprecated:
        return deprecatedSince.valid() &&
               detail::abiVersionIsZero(removedSince) &&
               detail::abiVersionAtLeast(deprecatedSince, introduced);
    case AbiSymbolState::Removed:
        if (!removedSince.valid() ||
            !detail::abiVersionAtLeast(removedSince, introduced))
            return false;
        if (detail::abiVersionIsZero(deprecatedSince))
            return true;
        return deprecatedSince.valid() &&
               detail::abiVersionAtLeast(deprecatedSince, introduced) &&
               detail::abiVersionAtLeast(removedSince, deprecatedSince);
    }
    return false;
}

inline bool AbiSymbolPolicyManifest::valid() const noexcept {
    if (!abiVersion.valid() ||
        !detail::visibleAsciiIdentifier(manifestId, maxManifestIdBytes) ||
        symbols.size() > maxSymbols)
        return false;

    std::string_view previousName;
    for (const auto& symbol : symbols) {
        if (!symbol.valid() ||
            !detail::abiVersionAtLeast(abiVersion, symbol.introduced))
            return false;
        if (!previousName.empty() && previousName >= symbol.name)
            return false;
        previousName = symbol.name;
    }
    return true;
}

inline const AbiSymbolLifecycle*
AbiSymbolPolicyManifest::find(std::string_view symbolName) const noexcept {
    for (const auto& symbol : symbols) {
        if (symbol.name == symbolName)
            return &symbol;
    }
    return nullptr;
}

} // namespace RinRuntime

#endif /* RINRUNTIME_ABI_SYMBOL_POLICY_HPP */
