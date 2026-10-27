# Public API licenses

`public-api-license-manifest.json` maps each RinRuntime and RinOS-SDK public
header installed by RinRuntime to its source repository, source path, and
file-level SPDX license. The SPDX declaration on a header controls that file;
the two MIT `LICENSE` files do not replace an explicit GPL declaration.

The installed license bundle keeps both repository MIT notices and the GPL-2.0
terms used by some public headers. Validate source and installed packages with
`scripts/check_public_api_license_manifest.py --sdk-root <resolved-sdk-path>`
and `scripts/check_public_api_license_manifest.py --installed-prefix <prefix>`.
