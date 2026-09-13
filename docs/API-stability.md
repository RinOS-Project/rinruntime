# RinRuntime API stability

The public layer is split into two contracts:

- header-only application models (`Widget`, controls, layout, accessibility,
  text, and bounded archive planning), and
- C service-client admission records (`portal.h`).

`RINRUNTIME_API_VERSION == 1` and the IPC protocol version are independent
negotiation values. Every wire record is fixed-width, versioned, and
size-prefixed. Portal tokens
carry only an opaque capability and owner/generation identity; they never carry
paths, native handles, process pointers, or private credentials. Stale or
malformed records are rejected before a service operation is attempted.

Enum values are append-only; reserved fields must be zero. New APIs are added
under the semantic-versioning policy and deprecated entries remain available
through one compatibility cycle before removal. C++ model headers are source
stable within a major version; consumers should not persist C++ object layout
or use it as a binary plugin ABI.

Window-server, filesystem-owner, crash-daemon, credential-owner, printing
backend, and package-install implementations are not part of this repository.
OS-Core connects them through authenticated adapters.
