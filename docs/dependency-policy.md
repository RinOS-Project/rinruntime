# Dependency policy

RinRuntime public headers include only the C/C++ standard library and
`RinOS-SDK`-compatible fixed-width types. They do not include `src/kernel`,
`src/services`, `src/drivers`, `src/apps`, or any OS-Core private header.

The pure models do not open files, access a compositor, discover hardware, or
invent a service result. Consumers provide authenticated adapters for those
operations; an absent or rejected adapter remains an explicit error.
