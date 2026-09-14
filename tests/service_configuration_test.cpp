/* SPDX-License-Identifier: MIT */

#include <cassert>

#include "../include/rinruntime/service_configuration.hpp"

int main() {
    RinRuntime::ServiceConfiguration configuration;
    configuration.serviceId = "resolved";
    configuration.displayName = "Rin Resolver";
    configuration.memoryLimitBytes = 64u * 1024u * 1024u;
    configuration.dependencies.push_back("network");
    configuration.optionalDependencies.push_back("telemetry");

    assert(configuration.valid());
    assert(configuration.dependsOn("network"));
    assert(!configuration.dependsOn("telemetry"));

    configuration.optionalDependencies.push_back("network");
    assert(!configuration.valid());
    configuration.optionalDependencies.pop_back();

    configuration.dependencies.push_back("aaa");
    assert(!configuration.valid());

    RinRuntime::ServiceConfiguration invalid;
    invalid.serviceId = "bad/id";
    invalid.displayName = "Invalid";
    assert(!invalid.valid());
    invalid.serviceId = "service";
    invalid.displayName = "bad\nname";
    assert(!invalid.valid());
    return 0;
}
