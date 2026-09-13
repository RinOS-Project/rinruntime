# Contributing to RinRuntime

Keep application models renderer-independent and keep service boundaries
explicit. Public records must be size/version prefixed, bounded, and
failure-atomic. Do not add a private OS-Core include, a process pointer, a
filesystem path to a capability token, or a success path that does not have an
authenticated owner.
