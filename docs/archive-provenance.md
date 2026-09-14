# Archive backend boundary

The public archive headers provide deterministic, bounded metadata planning and
the built-in raw DEFLATE, GZIP, strict ustar TAR, TAR.GZ, and ordinary ZIP
codecs.  They do not open a filesystem path, create a symlink, or publish a
filesystem transaction.  No third-party codec is linked into `RinRuntime`.

The codecs operate on caller-owned bytes or bounded caller-owned source/sink
callbacks.  Filesystem and service providers must validate their own
authority, and must discard staging output when a codec reports malformed
input, a limit, cancellation, or a sink failure.

Archive plans reject symbolic-link entries, absolute member names, `..`
components, excessive depth, and decompression ratios above the bounded
policy.  A provider that needs link semantics must use a separate privileged
policy and must not reinterpret an `ArchivePlan` as authorization to escape
the extraction root.
