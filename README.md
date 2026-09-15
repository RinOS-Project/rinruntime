# RinRuntime public window API

`rinruntime` exposes the native-window transport through `window.h` and the
C++ `RinRuntime::Window` wrapper.  Rendering is a borrowed-frame operation:

```cpp
#include <rinruntime/window.hpp>
#include <aquamarine.h>

RinRuntime::Window window("Hello", 0, 0, 640, 480);
window.onPaint([](AqSurface& surface) {
    aq_surface_clear(&surface, AQ_RGB(24, 32, 48));
});
window.paint();
```

`currentRenderSurface()` and `currentRenderFont()` are valid only on the
thread and during the callback's active frame.  The compositor owns the
surface mapping; applications must not retain those pointers or inspect a
physical framebuffer.  The C API in `render.h` provides the same acquire,
release, and present lifecycle without exposing a frame-context structure.

The CMake build enables the real Unix compositor client with
`RINRUNTIME_BUILD_GUI=ON` (the default on non-Windows hosts).  It consumes the
public SDK headers and the standalone `Aquamarine::Aquamarine` target only.

For a RinOS target image, opt into `RINRUNTIME_BUILD_RLL` (or Meson's
`-Dbuild_rll=true`).  The route invokes RinCompiler `rcc` for every configured
C source, links with `rld --shared`, and requires `rinsign`, a private key, a
matching public key, and explicit dependency `.rll` images.  The signed image
is atomically published only after the complete route succeeds; missing
toolchain inputs or dependencies are errors, and no host-library or unsigned
fallback is emitted.

The public C++ runtime also provides the backend-independent bounded
`EventLoop` model in `event_loop.hpp`.  POSIX hosts may opt into the
`PollEventLoopBackend` adapter in `event_loop_poll.hpp`; it owns only the
userspace `poll(2)` translation, while RinOS wait syscalls and production IPC
owners remain target-side adapters through `EventLoop::WaitFunction`.

RinOS applications may opt into `RinEventLoopBackend` in
`event_loop_rin.hpp`. It translates the same bounded requests to the public
`rin_wait_set_*` SDK contract and keeps the wait-set handle private to the
adapter. The adapter has compile-time checks against the public
`RIN_WAIT_EVENT_*` bit contract, so the kernel producer and userspace model
cannot silently drift into different masks. The EventLoop model and both
userspace adapters are public runtime; the kernel owns only the wait-set
syscall and IPC readiness producers.

The public runtime also provides the bounded `DownloadPartialReceipt`,
`DownloadRangeRequest`, and `DownloadRangeTransportAdapter` contracts. Receipt
decoding rejects non-zero reserved wire bytes and malformed identity/offset
fields. The callback context is optional, so a stateless owner may pass a null
cookie. A caller may omit cancellation entirely; when supplied, its callback
preserves `Cancelled` as a distinct state and the owner is aborted after
admission. The adapter is intentionally usable by ordinary applications and
external toolkits: its owner may be an HTTP range source, a local/object-store
source, or another bounded byte provider. Authentication, authorization,
HTTPS/TLS, partial-byte storage, and Browser File Portal publication remain
outside this generic public transport contract.

The public v1 transport callback table accepts both the original fixed prefix
and the extended table containing the optional cancellation callback. Older
owners therefore remain usable without inventing a cancellation context; a
future incompatible table must use a new ABI version.

`clipboard.h` provides the public application text clipboard client.  It
validates the UTF-8 byte bound and uses the public GUI syscall adapter with
failure-atomic output handling.  The private kernel broker remains the owner
of capability checks, per-user ownership, generation, locale metadata, and
the clipboard store; those private details are not required by ordinary
applications or external toolkits.

The public TLS client-certificate transport keeps only the bounded TLS wire
certificate list and opaque signer capability. `reset()` and all rejected
signature paths use an optimization-resistant clear for copied certificate,
capability, and caller signature bytes. Private keys, certificate stores,
keyrings, and HTTPS socket ownership remain outside this public signer
transport.

`timezone.hpp` provides the backend-independent `ClockReading`,
`TimeZoneSnapshot`, and `TimeZoneTransition` models. Snapshots validate bounded
timezone identifiers, offsets, abbreviations, ordered DST transitions, and
checked local-time conversion. A private clock/timezone owner may populate a
snapshot from TZif/ICU data; the public model owns no syscall, RTC, catalog,
filesystem, or persistence boundary, so ordinary applications and external
tooling can consume the same contract.

`cursor.h` provides the backend-independent `RinRuntimeCursorFrameV1` and
`RinRuntimeCursorImageV1` views. Pixel storage and frame arrays remain
caller-owned; dimensions, stride, hotspot, duration, frame count, and storage
limits are validated before a private CUR/ICO/ANI loader or compositor owner
publishes a frame. The public model has no cursor path, theme root, allocator,
or compositor handle, so ordinary applications and external toolkits may use
the same bounded ARGB contract.

`abi_policy.hpp` provides the backend-independent part of the library ABI
policy: same-major/minor-floor compatibility and append-only struct-prefix
checks. SONAME, symbol export/versioning, deprecation/removal, signatures,
and loader admission remain private packaging/loader responsibilities.

`package_metadata.hpp` provides the same bounded package identity, numeric
version, dependency ordering, and entry-point validation to ordinary
applications and external package tooling. It is a pure model: package
signatures, private keys, installed roots, filesystem publication, and kernel
admission remain private owners.

`package_metadata_json.hpp` provides the matching bounded JSON parser. It
uses public `rinjson` limits and converts package identity, dependency ranges,
entry points, publisher generation, and size fields failure-atomically into the
public model. Repository authentication, signatures, installed-root
publication, and kernel admission remain private owners.

`update_metadata.hpp` provides the corresponding bounded update description:
product/update identity, target version, channel, applicability floor, release
notes, and sorted package artifacts with exact sizes and SHA-256 digests. It has
no URL, pathname, signature, private key, socket, staging handle, or install
operation, so ordinary applications and external tooling can validate the same
metadata while a repository/updater remains the private authenticated owner.

`update_metadata_json.hpp` provides the matching bounded JSON parser. It uses
the public `rinjson` limits, rejects duplicate keys and malformed fields, and
clears the output model on every failure. JSON parsing is public and reusable
by ordinary applications and external package tooling; repository
authentication, HTTPS/TLS, signature verification, staging, and installation
remain private updater owners.

The archive headers are public, backend-independent codec contracts.  The
DEFLATE, GZIP, strict ustar TAR, TAR.GZ, and ordinary ZIP readers consume
caller-owned bytes or bounded callbacks and never open paths or publish files.
`ArchiveDeflateSource` accepts an exact compressed-size pull callback with a
fixed 4 KiB input window, so streaming owners do not need to expose a file or
socket to the codec.  `ArchiveDeflateEncoder` provides the generic deterministic
stored encoder plus bounded fixed-run and dynamic-literal authoring helpers.
Filesystem extraction, archive service IPC, and File Portal publication remain
private RinOS adapters.

The standalone `rincompression/deflate.hpp` header provides the generic
bounded deterministic stored-DEFLATE encoder. `rinruntime/archive_deflate.hpp`
keeps archive-specific source and authoring adapters as a compatibility layer;
archive policy, filesystem extraction, service IPC, and File Portal publication
remain outside the compression library.

The public `rincompression/lz4.hpp` header provides bounded raw LZ4 block
encoder/decoder contracts with failure-atomic caller-owned output and optional
cancellation. The encoder is deterministic and literal-only, leaving denser
match-finding strategies to a private owner. The public codec does not parse
LZ4 frames, open files, or publish extracted data; frame, filesystem, service,
and portal ownership remains with the private adapter.
