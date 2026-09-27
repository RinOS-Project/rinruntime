/* SPDX-License-Identifier: MIT */

#include <cassert>

#include "../include/rinruntime/abi_policy.hpp"
#include "../include/rinruntime/abi_symbol_policy.hpp"

int main() {
    const RinRuntime::AbiVersion provider{1u, 4u};
    assert(provider.valid());
    assert(RinRuntime::abiVersionCompatible(provider, {1u, 0u}));
    assert(RinRuntime::abiVersionCompatible(provider, {1u, 4u}));
    assert(!RinRuntime::abiVersionCompatible(provider, {1u, 5u}));
    assert(!RinRuntime::abiVersionCompatible(provider, {2u, 0u}));
    assert(!RinRuntime::abiVersionCompatible(provider, {0u, 1u}));

    assert(RinRuntime::abiStructPrefixCompatible(32u, 24u));
    assert(RinRuntime::abiStructPrefixCompatible(32u, 24u, 32u));
    assert(!RinRuntime::abiStructPrefixCompatible(23u, 24u));
    assert(!RinRuntime::abiStructPrefixCompatible(33u, 24u, 32u));

    RinRuntime::AbiSymbolPolicyManifest manifest;
    manifest.abiVersion = {1u, 4u};
    manifest.manifestId = "rinruntime";
    manifest.symbols = {
        {"rin_download_range", RinRuntime::AbiSymbolState::Stable, {1u, 0u}, {}, {}},
        {"rin_old", RinRuntime::AbiSymbolState::Deprecated, {1u, 0u}, {1u, 2u}, {}},
        {"rin_removed", RinRuntime::AbiSymbolState::Removed, {1u, 0u}, {1u, 2u}, {1u, 4u}},
    };
    assert(manifest.valid());
    assert(manifest.find("rin_old") != nullptr);
    assert(manifest.available("rin_download_range"));
    assert(manifest.available("rin_old"));
    assert(manifest.deprecated("rin_old"));
    assert(!manifest.available("rin_removed"));
    assert(manifest.deprecated("rin_removed"));
    assert(!manifest.available("rin_missing"));

    auto invalid = manifest;
    invalid.symbols[2].removedSince = {1u, 0u};
    assert(!invalid.valid());
    invalid = manifest;
    std::swap(invalid.symbols[0], invalid.symbols[1]);
    assert(!invalid.valid());
    invalid = manifest;
    invalid.symbols[0].introduced = {2u, 0u};
    assert(!invalid.valid());
    invalid = manifest;
    invalid.symbols[2].deprecatedSince = {1u, 5u};
    assert(!invalid.valid());
    return 0;
}
