# RinRuntime

RinRuntime is the public RinOS application model and service-client boundary.
It provides backend-independent widgets, accessibility, layout, bounded text
editing, archive admission policy, cancellation, and versioned portal
capability records. Private compositor/service/provider implementations remain
outside this repository.

## Standalone host build

```text
cmake -S . -B build -DRINRUNTIME_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Use `-DRINRUNTIME_BUILD_SHARED=ON` for the shared-library policy. The native
`.rll` packaging path is owned by the RinOS SDK/package toolchain and is not
needed by the host library or its tests.

The C++ entry point is `<rinruntime/rinruntime.hpp>`. C service-client
contracts are available from `<rinruntime/portal.h>`.
