/* SPDX-License-Identifier: MIT */

#include <cassert>

#include "../include/rinruntime/application_data.hpp"

int main() {
    RinRuntime::ApplicationDataIdentity owner;
    owner.userId = 7u;
    owner.applicationTag = 11u;
    owner.packageGeneration = 3u;
    assert(RinRuntime::ApplicationDataPolicy::validIdentity(owner));

    RinRuntime::ApplicationDataIdentity requester = owner;
    assert(RinRuntime::ApplicationDataPolicy::accessAllowed(
        RinRuntime::ApplicationDataKind::Data, owner, requester));
    assert(RinRuntime::ApplicationDataPolicy::cacheCleanupAllowed(
        RinRuntime::ApplicationDataKind::Cache, owner, requester, true));

    requester.packageGeneration = UINT64_MAX;
    assert(!RinRuntime::ApplicationDataPolicy::validIdentity(requester));
    assert(!RinRuntime::ApplicationDataPolicy::accessAllowed(
        RinRuntime::ApplicationDataKind::Data, owner, requester));
    assert(!RinRuntime::ApplicationDataPolicy::cacheCleanupAllowed(
        RinRuntime::ApplicationDataKind::Cache, owner, requester, true));

    owner.packageGeneration = UINT64_MAX;
    assert(!RinRuntime::ApplicationDataPolicy::validIdentity(owner));
    assert(!RinRuntime::ApplicationDataPolicy::accessAllowed(
        RinRuntime::ApplicationDataKind::Data, owner, requester));
    return 0;
}
