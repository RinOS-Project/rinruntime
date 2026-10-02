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
Timer and wait IDs carry a non-zero generation.  The generation allocator is
failure-closed at `UINT32_MAX` instead of wrapping, and `clear()` never resets
that lifetime state, so a stale ID cannot become valid again after a long-lived
loop has recycled a slot.

The canonical `rinruntime/rinruntime.hpp` umbrella includes the public
`RinEventLoopBackend` userspace adapter on every target and includes
`PollEventLoopBackend` on POSIX targets. The former translates to the public
SDK wait-set ABI; the latter owns only POSIX `poll(2)` mapping. Kernel wait
ownership, readiness producers, and service authority remain outside the
public runtime. The generic `EventLoop::WaitFunction` seam also accepts a
null callback context for stateless application-owned adapters; concrete
adapters that retain clock or wait-set state still require their caller-owned
backend object, and neither form exposes kernel wait authority.

The canonical `rinruntime/rinruntime.hpp` umbrella includes both public
Unicode adapters, `unicode.h` and `unicode.hpp`, so ordinary applications and
external toolkits can use the bounded UTF-8, grapheme, normalization,
comparison, locale, date/time, number, and case-fold contracts from one public
include. Unicode data and locale catalog ownership remain in the public
library snapshot/private data owner; the umbrella grants no filesystem or
service authority.

The same canonical umbrella includes `known_folders.hpp` alongside the C
`known_folders.h` ABI. `RinRuntime::knownFolder()` and
`RinRuntime::applicationDirectory()` are bounded location-discovery helpers
for ordinary applications and external toolkits; they return caller-owned
strings and do not grant file access, File Portal authority, or package/RinFS
ownership. Sandboxed applications still use their authenticated storage
capability rather than treating this convenience API as an ambient access
path.

`unicode.hpp` supplies the text model's bounded UTF-8 grapheme stepping. Its
thin C adapter delegates to the public `libunicode` snapshot, so C++ editing,
the C runtime, and `rinicud` use the same CRLF, combining/spacing mark, Hangul,
regional-indicator, and extended-pictographic ZWJ boundary contract. Full
Unicode GraphemeBreakProperty coverage and locale-specific behavior remain
separate `libunicode`/`libi18n` data-owner work; the public helper never loads
a database or filesystem resource.

The inline UTF-8 validator checks the remaining byte span before reading
continuation bytes. Truncated 2-, 3-, and 4-byte sequences therefore fail
closed without a size_t-underflow out-of-bounds read; callers still own the
input and no replacement character is silently inserted by this validator.

The C Unicode adapter also forwards `RinRuntimeUnicodeDateTime` to
`rin_unicode_locale_format_datetime`.  Applications and external toolkits can
use the bounded `%c`/`%x`/`%X` locale formatter through the public runtime
without including LibUnicode's internal adapter headers; locale data and
timezone ownership remain outside the runtime.

The adapter also forwards the bounded full and locale-aware case-fold
functions.  The default Unicode 13.0.0 mapping is shared with LibUnicode,
while the supported `tr`/`az` BCP-47 and POSIX names select the Turkic
U+0049/U+0130 mapping.  Locale data ownership and the remaining
SpecialCasing profiles stay outside this public runtime contract.

The C Unicode adapter also forwards the bounded LibUnicode comparison path.
UTF-8 inputs use lossy replacement for ill-formed sequences, while UTF-32
inputs are validated before comparison; invalid or unbounded input sorts after
valid input.  The public subset applies NFKD decomposition, full case-fold,
and canonical combining-class ordering.  Full UCA and locale weighting remain
outside this public runtime contract.

The adapter also forwards bounded locale-name canonicalization.  POSIX and
BCP-47 spellings, `C`/`POSIX`, and the supported `-u-nu-*` numbering-system
extension are resolved to an immutable catalog ID without exposing the
catalog owner.  Unknown names, malformed extensions, and insufficient output
capacity clear the caller-owned buffer and fail closed.

The same C adapter forwards the bounded integer, decimal, and currency
formatters.  Their borrowed locale and number inputs retain LibUnicode's
fixed scan bounds and failure-atomic output behavior, while locale data,
currency policy, and filesystem ownership remain outside the public runtime.
The CMake, Meson, and target `.rll` source graphs include LibUnicode's locale
adapter alongside `core.c`, so these public forwarding symbols are linked
rather than left as source-only declarations.

The canonical `rinruntime/rinruntime.hpp` umbrella also exposes public
`libi18n` through `rin_i18n.h`. Ordinary applications and external toolkits
can use the caller-owned `RinI18nCatalog`/`RinI18nArg` models and bounded
lookup, plural, format, and resource-adapter APIs from the same public include
boundary. Resource reading is delegated to a caller-owned bounded callback;
locale selection, catalog publication, filesystem authority, and persistence
remain private owner responsibilities.
The CMake, Meson, and target `.rll` source graphs include the bounded
`rin_i18n.c` implementation so linking `RinRuntime` resolves this public
adapter without requiring a private owner library.

The public LibUnicode normalization entry points treat a null source as an
empty input only after validating the requested NFD/NFC/NFKD/NFKC form.  An
unsupported form therefore fails closed and clears the caller's destination
even when the source pointer is null; the same rule applies to UTF-8 and
UTF-32 callers.

RinOS applications may opt into `RinEventLoopBackend` in
`event_loop_rin.hpp`. It translates the same bounded requests to the public
`rin_wait_set_*` SDK contract and keeps the wait-set handle private to the
adapter. The adapter has compile-time checks against the public
`RIN_WAIT_EVENT_*` bit contract, so the kernel producer and userspace model
cannot silently drift into different masks. The EventLoop model and both
userspace adapters are public runtime; the kernel owns only the wait-set
syscall and IPC readiness producers. Direct adapter callers also get
fail-closed validation for zero handles, unsupported event bits, and duplicate
wait IDs before any wait-set items are published. Both deadline adapters also
reject a monotonic-clock rollback before publishing a new SDK wait-set item
list and before recomputing a timeout, so a stale deadline cannot become an
unbounded sleep after a repeated or interrupted wait. The SDK adapter repeats
the deadline sample after item publication to avoid extending a finite wait by
the publication syscall itself. If that second sample detects a rollback, it
restores the previously published item list; if restoration fails, it closes
the wait-set rather than leaving a stale target-side request usable.
`RinEventLoopBackend::reset()` also clears the retired wait-item bytes and
clock sample before a new wait-set session is initialized, so a reconnect with
a fresh clock epoch cannot be rejected as an intra-session rollback.

Private RinOS services may compose `PollEventLoopBackend` for local POSIX fd
readiness (the archive service does so for its authenticated server socket).
That composition does not publish service authority, paths, File Portal
capabilities, or kernel wait-set implementation through the public runtime.

`render_context.hpp` keeps the same boundary for fonts.  The public runtime
offers `setSystemUiFontLoader()` as a borrowed, caller-owned callback and
falls back to Aquamarine's built-in font when no owner is registered.  It does
not choose a locale, open `/res/fonts`, retain a descriptor, or own a resource
path.  Desktop registers its private locale/resource adapter; an ordinary
application or external toolkit may register a different bounded font owner.

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
The canonical `rinruntime/rinruntime.hpp` umbrella exposes the same adapter;
the `rinruntime-model` host contract exercises it with a caller-owned range
source without importing any Browser or service owner.

`DownloadPartialReceipt::encode()` also clears the caller-owned output range
on failure, bounded to the receipt wire size. This prevents stale durable
receipt bytes from being reused after an invalid or undersized encode.
The decode, request preparation, range-header construction, and response
construction paths are failure-atomic under exception-enabled builds: an
allocation failure clears the candidate/output state and returns failure
without publishing a partial validator or header. The transport adapter also
catches an owner `std::bad_alloc` from `begin()`, aborts the admitted range,
and returns to `Idle` without exposing a partial response.

The public v1 transport callback table accepts both the original fixed prefix
and the extended table containing the optional cancellation callback. Older
owners therefore remain usable without inventing a cancellation context; a
future incompatible table must use a new ABI version.

`readDownloadRangeToBuffer()` is the optional caller-owned convenience helper
for this same public transport. It revalidates the admitted response length,
reads in at most 64 KiB chunks, rejects early EOF and trailing bytes, and
scrubs the bounded caller-owned buffer on invalid admission, begin/response
rejection, read failure, or trailing bytes before returning with `outputSize`
zero. The adapter also clamps
each owner callback to the admitted remaining range (while retaining a final
zero-byte EOF probe) and scrubs
the caller-owned read buffer after a direct callback failure or cancellation,
so a failed direct `read()` cannot leave partial transfer bytes behind. It does
not authenticate the source, persist partial bytes, or publish a File Portal
object. A failed `begin()` is not followed by a second abort, so the adapter's
distinct cancellation state remains observable to the caller.

`drag_drop.hpp` provides the public `DragDropSession` model for ordinary
applications and external toolkits. It copies only bounded MIME payloads and
labels, tracks a generation-bound session lifecycle, and requires an explicit
single Copy/Move/Link acceptance before a drop. It does not carry paths,
descriptors, sockets, compositor handles, or portal authority; private
compositor, File Portal, and permission-broker adapters decide whether an
accepted payload may actually be delivered.
`DragDropPayload::valid()` uses the same strict MIME and UTF-8 checks as the
session admission path, so directly constructed payloads cannot bypass the
public validation boundary.

`clipboard.h` provides the public application text clipboard client.  It
validates the UTF-8 byte bound and uses the public GUI syscall adapter with
failure-atomic output handling.  The private kernel broker remains the owner
of capability checks, per-user ownership, generation, locale metadata, and
the clipboard store; those private details are not required by ordinary
applications or external toolkits.

`file_portal_startup.h` provides a generic custom-app consumer for the one-shot
fd-198 child handoff. It validates the fixed request and display label, opens
the authenticated token through `rinruntime_file_portal_open()`, and returns
the descriptor with an opaque document identity. The parent handshake is
explicit; paths and launcher authority are not passed through argv or the
environment.

The public TLS client-certificate transport keeps only the bounded TLS wire
certificate list and opaque signer capability. `bind()` copies both into
transport-owned storage, so the request retains no pointers into the caller's
temporary response. It volatile-clears the one-shot capability after a signing
callback returns, whether signing succeeds or fails. Failed or rejected
signing also clears the declared signature output when its capacity is within
the 512-byte transport bound; `reset()` clears the copied certificate and
capability. The signer cookie is optional, so a stateless caller-owned signer
may pass null while the capability and request identity still bind the
operation. Private keys, certificate stores, keyrings, and HTTPS socket
ownership remain outside this public signer transport.

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
checks. `abi_symbol_policy.hpp` adds a bounded, sorted lifecycle manifest for
stable, optional, deprecated, and removed public symbols; it is reusable by
ordinary applications and external tooling without exposing symbol addresses
or loader authority. SONAME, linker export/versioning, lifecycle enforcement,
signatures, and loader admission remain private packaging/loader
responsibilities.

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

`package_metadata_catalog.hpp` and `package_metadata_catalog_json.hpp` (also
exported by the `rinruntime.hpp` umbrella) provide a bounded, generation-tagged
package listing for ordinary applications and external package tooling. Entries
must be valid and sorted uniquely by package ID, and malformed or unordered
snapshots clear the output. The catalog is repository-neutral: URLs,
authentication, signatures, trust provisioning, artifact selection, installed
roots, and install/launch authority remain private repository and installer
owners.

`application_metadata.hpp` and `application_metadata_json.hpp` provide the
same split for application descriptors. The public parser validates bounded
identifiers, strict UTF-8 display/path/MIME text, relative entry points,
sorted categories and MIME types, while package paths, icon/resource loading,
signatures, and installed-application publication remain private owners.

`application_metadata_catalog.hpp` and
`application_metadata_catalog_json.hpp` (also exported by the
`rinruntime.hpp` umbrella) add a bounded, generation-tagged list of those
descriptors for ordinary applications and external tooling. Entries
must be valid and sorted uniquely by application ID, and failed parsing clears
the output. The catalog generation is only an opaque snapshot value; repository
URLs, authentication, signatures, installed roots, trust provisioning, and
launch authority remain private repository/installer/launcher owners.

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

`update_metadata_catalog.hpp` and `update_metadata_catalog_json.hpp` (also
exported by the `rinruntime.hpp` umbrella) provide a bounded, generation-tagged
update snapshot for ordinary applications and external package tooling. Each
entry reuses `UpdateMetadata` artifact/version/digest validation, and the
catalog requires sorted-unique update IDs with failure-atomic output. It does
not authenticate a repository, select a download URL, verify a signature,
stage bytes, or authorize installation/reboot; those remain private updater
owners.

The archive headers are public, backend-independent codec contracts.  The
DEFLATE, standalone GZIP, strict ustar TAR, TAR.GZ, and ordinary ZIP readers consume
caller-owned bytes or bounded callbacks and never open paths or publish files.
`ArchiveDeflateSource` accepts an exact compressed-size pull callback with a
fixed 4 KiB input window, so streaming owners do not need to expose a file or
socket to the codec.  `ArchiveDeflateEncoder` provides the generic deterministic
stored encoder plus bounded fixed-run and dynamic-literal authoring helpers.
Archive DEFLATE decoding also rejects streams exceeding the public
`RINRUNTIME_ARCHIVE_DEFLATE_BLOCK_LIMIT` of 65,536 blocks, in addition to the
expanded-content and compression-ratio policies. Deadline-aware decoder and
sink overloads poll a caller-owned monotonic deadline predicate and return
`ArchiveDeflateResult::Deadline` with failure-atomic output cleanup; the
`ArchiveGzipReader` memory/source and sink overloads carry the same deadline
contract through header staging and raw DEFLATE decoding. The existing
cancellation overloads remain source-compatible. `ArchiveZipReader` adds
deadline-aware central-directory parsing plus memory and sink entry reads;
stored-entry CRC/copy and DEFLATE entry work are checked before publication.
`ArchiveTarReader` and `ArchiveTarGzipReader` provide the same deadline
boundary for strict ustar parsing, GZIP-to-TAR composition, and sink delivery.
`ArchiveTarReader::readEntryToSink()` provides the same bounded, at-most-64 KiB
caller-owned staging path for regular TAR entries, and
`ArchiveTarGzipReader` delegates to it after its bounded GZIP staging step. A
sink failure is not publication and directories produce no data callback. Sink
contexts are optional, so stateless general-application callbacks may pass a
null cookie; filesystem extraction, archive service IPC, and File Portal
publication remain private RinOS adapters.

`archive_container.hpp` maps a standalone GZIP member to one bounded
caller-owned `<stream>` entry, while TAR.GZ remains a TAR entry container.  The
adapter also maps the bounded 7z Copy／Delta／BCJ／BCJ2／LZMA／LZMA2 subset and XZ
decoded stream to the same `<stream>` contract.  It does not infer package
trust or publish the stream to a filesystem.

`archive_xz.hpp` provides the public `ArchiveXzReader` structural inspector.
It verifies the bounded XZ stream header/footer/index, block-header CRCs,
filter-property bounds, block padding, record sizes, and expanded-size limits
without opening a path.  `decodeStoredLzma2()` adds a failure-atomic,
caller-owned output path for check type 0, CRC32 (type 1), or CRC64 (type 4)
blocks containing both LZMA2 stored chunks (`0x01`/`0x02`) and range-coded
chunks, or an ordered bounded chain of Delta (`0x03`, distance 1..256), x86
BCJ (`0x04`, four-byte start offset), PowerPC BCJ (`0x05`, no properties), ARM
BCJ (`0x07`, no properties), ARM Thumb BCJ (`0x08`, no properties), ARM64 BCJ
(`0x0a`, no properties), SPARC BCJ (`0x09`, no properties), IA64 BCJ (`0x06`,
no properties), and RISC-V BCJ (`0x0b`, no properties) prefilters plus one
LZMA2 filter (`0x21`), including the
standard block-padding/check ordering.  Delta, x86 BCJ, PowerPC BCJ, IA64 BCJ,
ARM BCJ, ARM Thumb BCJ, ARM64 BCJ, SPARC BCJ, and RISC-V BCJ output is applied
in reverse header order per block before the block check is verified.  Range-coded
state, dictionary references, cancellation, and deadline checks stay bounded
by the public content limit; unsupported, duplicate, or incomplete filter
chains and check types remain explicit `Unsupported` results.  Filesystem
extraction, archive service IPC, and File Portal publication remain private
owners.

`archive_7z.hpp` provides the public `Archive7zReader` envelope inspector and
the explicitly bounded `decodeStored()` subset.  The decoder accepts one
non-empty packed stream, bounded multiple folders when each folder is a
bounded linear plain Copy or raw Delta／BCJ filter coder chain of up to two
coders with regular substreams described by `SubStreamsInfo`,
one single BCJ2 coder
(`03 03 01 1b`) with four packed input streams, or empty regular
files/directories with no packed stream.  `FilesInfo` may also interleave those empty entries with the
decoded substreams.  The
single BCJ2 path validates the MAIN／CALL／JUMP／RC stream sizes, range-coded
branch decisions, exact output size, and complete input consumption.  Other
pipelines use a linear pipeline of up to four one-in/one-out Copy (`0x00`), Delta
(`0x03`, one-byte distance property), the XZ-compatible BCJ subset (`0x04`
through `0x0b`, with the x86 four-byte start-offset property), and LZMA
(`03 01 01` with its five-byte properties) or LZMA2 (`0x21`, one-byte
dictionary property) coders.  BindPairs, packed/final stream selection,
intermediate sizes, and optional single-file metadata/CRC records are
validated before failure-atomic caller-owned output is published.
The raw BCJ/Delta transforms reuse the public `ArchiveXzReader` filter helper;
arbitrary multi-stream coders, multi-folder coder chains, encryption,
filesystem extraction, archive service IPC, and File Portal publication remain
private or explicit `Unsupported` results.
The shared `ArchiveXzReader::decodeRawLzma()` helper owns only the bounded raw
range-coded codec; it does not parse 7z headers or publish bytes.  Multi-stream
coders, encryption, multiple folders, filesystem extraction, archive
service IPC, and File Portal publication remain private or `Unsupported`.
Arbitrary multi-stream graphs, multi-folder coder chains, encryption, and
malformed empty-stream metadata remain explicit `Unsupported` or malformed
results.  Its 7z VLI reader
consumes multi-byte extra bytes in the format's little-endian order and rejects
non-minimal encodings such as a zero value encoded with an extra byte, so
malformed header values do not reach the stored-copy path.

`backup_archive.hpp` adds the public `BackupArchiveReader` consumer for the
bounded RBK1 ZIP layout (`manifest.rbk1` plus one `payload/<item_id>` entry per
included declaration). It keeps the manifest and payload in caller-owned
memory, rejects missing/unknown/excluded members, and passes each payload to
the existing identity and migration checks. It does not open backup paths,
resolve Known Folders, authenticate package handoffs, read a File Portal
descriptor, or publish restored bytes; those remain private archive/service
owners.

The canonical `rinruntime/rinruntime.hpp` umbrella includes this memory-only
backup reader as well, so ordinary applications and external toolkits can
consume the bounded RBK1 contract without importing a private archive or File
Portal owner.

The C RBK1 manifest encoder clears `bytes_size_out` and the caller-owned
manifest output span on validation or capacity failure (bounded by
`RINRUNTIME_BACKUP_MANIFEST_STORAGE_MAX`), so a rejected replacement cannot
leave a previous manifest available to a caller.

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
subset for raw and RLE blocks plus direct-table or bounded-FSE, single- and
four-stream Huffman literals, with content-size, optional XXH64 checksum,
cancellation, and failure-atomic output validation. The public FSE tree path is
capped at accuracy seven and 128 decoded weight bytes; non-zero sequence
commands and external dictionaries return `Unsupported`. A private frame owner
may add those algorithms without changing the public filesystem or service
boundary.
The decoder also rejects frames containing more than `kZstdMaximumBlocks`
(65,536) blocks, including empty raw blocks, so block-count CPU amplification
fails closed as `Limit` without changing the public/private ownership split.
Null compressed input is rejected as `InvalidArgument`, including the zero-size
case, before the frame header is inspected.
The canonical `rinruntime/rinruntime.hpp` umbrella includes this codec for
ordinary applications and external toolkits; it does not grant filesystem,
service, Browser, or publication authority.

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

The public `ArchiveXzReader` rejects non-minimal XZ VLI encodings as malformed
input. XZ VLI values are required to use the minimum number of bytes; this
check is part of the bounded envelope inspector and does not add a decoder or
private archive owner to the public runtime.
