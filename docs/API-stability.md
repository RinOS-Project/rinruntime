# RinRuntime API stability

The public layer is split into two contracts:

- header-only application models (`Widget`, controls, layout, accessibility,
  text, and bounded archive planning), and
- C service-client admission records (`portal.h`).

Every wire record is fixed-width, versioned, and size-prefixed. Portal tokens
carry only an opaque capability and owner/generation identity; they never carry
paths, native handles, process pointers, or private credentials. Stale or
malformed records are rejected before a service operation is attempted.

Window-server, filesystem-owner, crash-daemon, credential-owner, printing
backend, and package-install implementations are not part of this repository.
OS-Core connects them through authenticated adapters.
