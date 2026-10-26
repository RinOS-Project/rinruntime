# Dependency policy

RinRuntime public headers include only the C/C++ standard library and
`RinOS-SDK`-compatible fixed-width types. They do not include `src/kernel`,
`src/services`, `src/drivers`, `src/apps`, or any OS-Core private header.

The C sources are built with `include/` and the public `RinOS-SDK/include/`
on their public include path. The build does not add the OS-Core root, a
sibling private library, or a private generated-header directory. A service
implementation must be injected by a separate authenticated adapter; the
public library never substitutes a successful result when that adapter is
absent.

The pure models do not open files, access a compositor, discover hardware, or
invent a service result. Consumers provide authenticated adapters for those
operations; an absent or rejected adapter remains an explicit error.

Dependency cache checkouts are kept beneath the configured cache root (the
build-local `rinruntime-deps` directory by default). The resolver rejects a
checkout or lock path that escapes that root or traverses a detected
symlink/junction/reparse point, and rejects `.`/`..` checkout directory names.
Set `RINRUNTIME_DEPENDENCY_CACHE_ROOT` to choose a different canonical cache
root explicitly.

The per-checkout lock is opened with no-follow semantics where the host
supports them, then checked against the opened descriptor and canonical path.
Non-regular files, reparse points, hard links, oversized lock files, and path
identity changes detected during validation are rejected before locking.
This narrows replacement races at lock acquisition; it does not claim immunity
to every concurrent mutation of the configured cache directory.
