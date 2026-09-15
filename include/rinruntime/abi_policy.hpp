/* SPDX-License-Identifier: MIT */
/* Backend-independent ABI compatibility policy for public consumers. */
#ifndef RINRUNTIME_ABI_POLICY_HPP
#define RINRUNTIME_ABI_POLICY_HPP

#include <cstdint>

namespace RinRuntime {

/* Public versioning is intentionally independent from a loader SONAME.  A
 * provider may serve an older application only when the major ABI is equal
 * and the provider's minor version is at least the application's minimum. */
struct AbiVersion final {
    std::uint16_t major = 0u;
    std::uint16_t minor = 0u;

    constexpr bool valid() const noexcept { return major != 0u; }
};

constexpr bool abiVersionCompatible(const AbiVersion& provider,
                                    const AbiVersion& minimum) noexcept {
    return provider.valid() && minimum.valid() &&
           provider.major == minimum.major && provider.minor >= minimum.minor;
}

/* Stable C structures may grow by appending fields.  A consumer must state
 * the minimum prefix it understands; a producer must never claim a shorter
 * prefix as a complete instance.  The upper bound is optional because a
 * caller may deliberately accept future fields it does not inspect. */
constexpr bool abiStructPrefixCompatible(std::uint32_t suppliedSize,
                                          std::uint32_t minimumSize,
                                          std::uint32_t maximumSize = 0u) noexcept {
    return suppliedSize >= minimumSize &&
           (maximumSize == 0u || suppliedSize <= maximumSize);
}

} // namespace RinRuntime

#endif /* RINRUNTIME_ABI_POLICY_HPP */
