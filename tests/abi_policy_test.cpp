/* SPDX-License-Identifier: MIT */

#include <cassert>

#include "../include/rinruntime/abi_policy.hpp"

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
    return 0;
}
