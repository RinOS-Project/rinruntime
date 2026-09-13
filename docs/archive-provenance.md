# Archive backend boundary

The public `ArchivePlan` is an admission and metadata model.  It does not
ship a gzip/deflate implementation, open a filesystem path, create a symlink,
or link a third-party codec into `RinRuntime`.  Method `8` is accepted only as
metadata for an authenticated provider; the provider must declare its own
license provenance before it is linked into an application.

Archive plans reject symbolic-link entries, absolute member names, `..`
components, excessive depth, and decompression ratios above the bounded
policy.  A provider that needs link semantics must use a separate privileged
policy and must not reinterpret an `ArchivePlan` as authorization to escape
the extraction root.
