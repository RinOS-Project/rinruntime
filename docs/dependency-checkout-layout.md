# Local dependency checkout layout confinement

The resolver derives each reusable local checkout location from the dependency
lock's Core gitlink path. Libraries under `public-base/libs/` may only reuse
their direct sibling checkout, and the SDK may only reuse
`public-base/RinOS-SDK`. An alternate path, an arbitrary parent traversal, a
symlink, or a Windows reparse point cannot redirect a local dependency lookup.

If the expected sibling is absent, dirty, or at another revision, the resolver
uses the existing isolated build cache. It does not mutate a sibling checkout.
Cache path confinement and full-commit pin checks remain in effect for that
route.

The lock's `requiredPaths` are checked against the same canonical dependency
root. Entries must use normalized slash-separated relative paths and resolve to
regular files inside the root. Parent traversal, drive/stream syntax, and
symlink/reparse-point components are rejected before CMake or Meson receives
the resolved dependency set.

This is a source change only. No build or test was run for this update. A clean
standalone clone and hosted GCC/Clang CMake/Meson install-consumer matrix remain
unverified, so `DEV-DIST-01` stays open.
