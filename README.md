# RinRuntime public window API

`theme.hpp` と `theme_json.hpp` は、backend-independentなThemeProfileと
bounded JSON／`TYPE_THEME` resource consumerを提供する。palette生成、認証済み
catalog publication、theme service、filesystem、window／compositor ownershipは
public runtimeに含めず、RinOS側のprivate adapterへ分離する。

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

`unicode.hpp` supplies the text model's bounded UTF-8 grapheme stepping. It
implements the common UAX #29 boundary rules needed by editing, including
CRLF, combining/spacing marks, Hangul syllable sequences, regional-indicator
pairs, and extended-pictographic ZWJ sequences. Full Unicode property data and
locale-specific behavior remain the separate `libunicode`/`libi18n` data-owner
task; the public helper never loads a database or filesystem resource.

RinOS applications may opt into `RinEventLoopBackend` in
`event_loop_rin.hpp`. It translates the same bounded requests to the public
`rin_wait_set_*` SDK contract and keeps the wait-set handle private to the
adapter. The adapter has compile-time checks against the public
`RIN_WAIT_EVENT_*` bit contract, so the kernel producer and userspace model
cannot silently drift into different masks. The EventLoop model and both
userspace adapters are public runtime; the kernel owns only the wait-set
syscall and IPC readiness producers. Direct adapter callers also get
fail-closed validation for zero handles, unsupported event bits, and duplicate
wait IDs before any wait-set items are published.

Private RinOS services may compose `PollEventLoopBackend` for local POSIX fd
readiness (the archive service does so for its authenticated server socket).
That composition does not publish service authority, paths, File Portal
capabilities, or kernel wait-set implementation through the public runtime.

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

`drag_drop.hpp` provides the public `DragDropSession` model for ordinary
applications and external toolkits. It copies only bounded MIME payloads and
labels, tracks a generation-bound session lifecycle, and requires an explicit
single Copy/Move/Link acceptance before a drop. It does not carry paths,
descriptors, sockets, compositor handles, or portal authority; private
compositor, File Portal, and permission-broker adapters decide whether an
accepted payload may actually be delivered.

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

`application_metadata.hpp` and `application_metadata_json.hpp` provide the
same split for application descriptors. The public parser validates bounded
identifiers, display text, relative entry points, sorted categories and MIME
types, while package paths, icon/resource loading, signatures, and installed
application publication remain private owners.

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

The public `rincompression/zstd.hpp` header provides a bounded Zstandard frame
subset for raw and RLE blocks, with content-size, optional XXH64 checksum,
cancellation, and failure-atomic output validation. Entropy-compressed blocks
and external dictionaries return `Unsupported`; a private frame owner may add
those algorithms without changing the public filesystem or service boundary.

`firewall_conntrack.h` provides filtering and pagination for a fixed-size,
caller-owned, immutable Firewall connection snapshot. It does not retrieve
kernel state or grant firewall authority; a private service must authenticate
and copy the snapshot before passing its records to RinRuntime. The live
packet observer, table owner, and kernel-to-Firewalld snapshot callback remain
private OS-Core code.

`firewall_namespace_policy.h` creates bounded, namespace-scoped default
policy guards in an ordinary Firewall ruleset. Host defaults remain in the
ruleset's default-action fields; non-host namespaces use their own exact-ID
rules and fall back to DROP when no namespace policy matches. Unscoped
non-system rules are host-only, and container rules must name a non-host
namespace. The helper owns no kernel or service authority; a private policy
owner still authenticates and atomically publishes the resulting ruleset.

`firewall_application.h` accepts a zero package generation only when the
context carries `RIN_FIREWALL_APPLICATION_FLAG_SYSTEM_PROCESS`. RinOS uses
generation zero for identities admitted by its immutable signed system image
catalog; the kernel supplies the descriptive flag when it constructs the
context. The flag and context shape do not authenticate arbitrary userland
input: a privileged Firewall service must still verify that the context came
from its trusted kernel owner.

## Public API contract

| Requirement | Contract |
| --- | --- |
| Purpose | RinRuntime provides public runtime facilities used across RinOS, including windowing and related platform-facing APIs, with interfaces under `include/rinruntime` and `include/rincompression`. |
| Supported API | The public headers under `include/rinruntime` and `include/rincompression` define the supported interfaces. The API surface is header-specific; consult the declaration and documentation for the exact contract of each facility. |
| Unsupported API | Internal implementation headers and undocumented behavior are not supported API. The library does not promise that every platform implements every optional facility identically. |
| ownership | Ownership is defined per public type and function. Callers must follow the declared create/destroy, retain/release, callback, and buffer lifetime rules; do not infer ownership from pointer type alone. |
| thread-safety | Thread-safety is defined per API. Treat mutable runtime objects and platform/window operations as thread-affine unless their public declaration explicitly permits concurrent use; synchronize shared state. |
| limits | Limits vary by facility and are documented alongside its public declarations. Validate caller-provided sizes and handle explicit limit errors; no universal unbounded-input contract is implied. |
| errors | Each API reports failures through its declared status/result mechanism or documented callback. Callers must check results and avoid relying on partially initialized outputs after failure. |
| ABI stability | Public C declarations form the C ABI; C++ interfaces may depend on compiler and standard library ABI. No universal cross-version ABI guarantee is published; rebuild consumers for the matching RinOS release. |
| security | RinRuntime APIs provide functionality, not an application sandbox. Validate untrusted input and use the OS service boundary for privileged operations; a public runtime call does not grant kernel or hardware authority. |
| build | CMake and Meson build definitions are provided. Build as part of RinOS or use the repository's declared build targets and public include directories. |
| test | A `tests` directory and build definitions are provided. Run the test targets exposed by the selected build configuration; there is no single configuration-independent command documented here. |
