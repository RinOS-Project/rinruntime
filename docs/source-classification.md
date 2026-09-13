# RinRuntime source classification

The former `libs/rinruntime` directory contains both reusable models and
RinOS service/provider implementations.  This public repository contains the
portable A/C rows below; the B/D rows remain adapter or OS-Core work and are
not smuggled into the public include path.

| Former source family | Classification | Public treatment |
| --- | --- | --- |
| widget, controls, layout, event, text editor, piece table | A: public runtime | Copied as backend-independent C++ models. |
| accessibility model and bounded tree policy | A/B | The model is public; a service transport must consume a versioned wire record. |
| `backup_restore.c` | B: public service client/policy | Canonical bounded RBK1 manifest encoder/decoder is public; the system coordinator is not. |
| `known_folders.c` | C: public utility | Only canonical path construction and bounded logical IDs are public. |
| `file_operation.c` | B/C | Execution is callback-based, so filesystem authority stays with an authenticated adapter. |
| `file_portal.c`, durable portal, chooser | B | Public contract is represented by opaque portal tokens and request validation; privileged broker code remains OS-Core. |
| `compositor_gui.c`, helpers | D: private provider | Socket, shared-memory, compositor and window-server implementation remain private. |
| `crash_service.c` | B: public policy adapter | Converts bounded session metadata into the SDK crashd registration record; the daemon and raw process memory remain private. |
| `crash_service_client.c` | B: public service client | Uses the SDK crashd wire/socket ABI. Endpoint absence, identity mismatch, timeout, and malformed replies remain explicit errors. |
| `accessibility_service_client.c` | B | Public tree model is present; service socket ownership stays with the SDK/OS-Core adapter. |
| `file_crypt.c`, `secure_folder.c` | D/B | Key ownership is delegated to RinTLS and the credential service; no key material is copied here. |
| `archive*.hpp` and `archive_policy.h` | A/C | Metadata planning and traversal/bomb policy are public; codec/filesystem providers are not. |
| `rin_runtime.c`, `rin_atexit_registry.c`, libc/libcxx glue | D | Process runtime and OS ABI glue remain private. |
| audio, serial, tray, wallpaper, resolver, theme, management clients | B/D | Each needs an SDK-owned wire contract before it can enter this public repository. |

Every public header in this repository is standalone against the C/C++
standard library and this repository's own headers.  No public implementation
is allowed to open a privileged endpoint or to turn a logical identifier into
authority without an authenticated adapter.
