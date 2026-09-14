# RinRuntime source classification

The former `libs/rinruntime` directory contains both reusable models and
RinOS service/provider implementations.  This public repository contains the
portable A/C rows below; the B/D rows remain adapter or OS-Core work and are
not smuggled into the public include path.

| Former source family | Classification | Public treatment |
| --- | --- | --- |
| widget, controls, layout, print-preview geometry, event, event loop, text editor, piece table | A: public runtime | Copied as backend-independent C++ models. `event_loop_poll.hpp` is a POSIX userspace adapter and `event_loop_rin.hpp` is the SDK wait-set userspace adapter; only target wait syscalls and IPC readiness producers remain OS-Core. |
| accessibility model and bounded tree policy | A/B | The model is public; a service transport must consume a versioned wire record. |
| `backup_restore.c` | B: public service client/policy | Canonical bounded RBK1 manifest encoder/decoder is public; the system coordinator is not. |
| `known_folders.c` | C: public utility | Only canonical path construction and bounded logical IDs are public. |
| `file_operation.c` | B/C | Execution is callback-based, so filesystem authority stays with an authenticated adapter. |
| `file_portal.c`, durable portal, chooser | B: public service client | Token/call ABI, bounded path/text validation, and the real client transports are public; privileged broker and filesystem authority remain OS-Core. |
| `file_operation_service_client.c` | B: public service client | Uses the authenticated FileOperation wire contract and reports unavailable, denied, malformed, and I/O outcomes without a success fallback. |
| `compositor_gui.c`, render context | B: public native-window client | Window lifecycle, input, shared-memory buffers, and presentation use the public compositor/window ABI; the compositor service and physical backend remain OS-Core. |
| `crash_service.c` | B: public policy adapter | Converts bounded session metadata into the SDK crashd registration record; the daemon and raw process memory remain private. |
| `crash_service_client.c` | B: public service client | Uses the SDK crashd wire/socket ABI. Endpoint absence, identity mismatch, timeout, and malformed replies remain explicit errors. |
| `accessibility_service_client.c` | B: public service client | Uses the SDK accessibility wire contract and returns transport/protocol errors; the accessibility daemon remains OS-Core. |
| `rin_serial_portal_protocol.*` | A/B: public wire client contract | Pointer-free serial portal frames and strict encode/decode helpers are public; serial device authority and the authenticated portal service remain OS-Core. |
| `rin_web_serial_portal.h` | B: public WebContent client contract | Web Serial device records and authenticated portal/file-operation callbacks are public; the default VFS/syscall adapter remains an OS-Core implementation. |
| `file_crypt.c`, `secure_folder.c` | D/B | Key ownership is delegated to RinTLS and the credential service; no key material is copied here. |
| `archive*.hpp` and `archive_policy.h` | A/C | Metadata planning, bounded DEFLATE/GZIP/TAR/TAR.GZ/ZIP codecs, and traversal/bomb policy are public; filesystem/service providers are not. |
| `rin_runtime.c`, `rin_atexit_registry.c`, libc/libcxx glue | D | Process runtime and OS ABI glue remain private. |
| audio service client | B: public service client | Uses the SDK audio wire/shared-ring contract; the audio daemon, device authority, and USB publication remain OS-Core. |
| serial device, tray, wallpaper, resolver, theme, management clients | B/D | Each still needs an SDK-owned wire contract before it can enter this public repository. |

Every public header in this repository is standalone against the C/C++
standard library and this repository's own headers.  The public RinRuntime
build consumes only `public-base/libs/rinruntime/src`, the public SDK, and
public-base libraries; it does not include or link `libs/rinruntime`.
No public implementation is allowed to open a privileged endpoint or to turn
a logical identifier into authority without an authenticated adapter.
