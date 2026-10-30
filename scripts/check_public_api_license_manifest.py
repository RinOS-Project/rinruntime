#!/usr/bin/env python3
"""Validate the first-party SDK/runtime header licensing inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path, PurePosixPath


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "licenses" / "public-api-license-manifest.json"
HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".inc"}
RUNTIME_TARGET_ONLY_HEADERS = {
    "include/rinruntime/pe_loader.h",
    "include/rinruntime/rin_cursor.h",
}
SPDX_RE = re.compile(r"SPDX-License-Identifier:\s*([A-Za-z0-9.+-]+)")
LICENSE_URLS = {
    "MIT": "https://spdx.org/licenses/MIT.html",
    "GPL-2.0-or-later": "https://spdx.org/licenses/GPL-2.0-or-later.html",
}


def _git(repository: Path, *arguments: str) -> str:
    repository = repository.resolve()
    command = ["git", "-c", f"safe.directory={repository.as_posix()}",
               "-C", str(repository), *arguments]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{' '.join(command)} failed: {detail}")
    return result.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _root_license(path: Path) -> str:
    first_line = path.read_text(encoding="utf-8-sig").splitlines()[0].strip()
    if first_line != "MIT License":
        raise RuntimeError(f"unsupported package root license in {path}: {first_line}")
    return "MIT"


def _tracked_headers(repository: Path, include_root: str,
                     exclude_crypt: bool = False,
                     exclude_paths: set[str] | None = None) -> list[Path]:
    output = _git(repository, "ls-files", "-z", "--", include_root)
    headers = []
    for item in output.split("\0"):
        if not item:
            continue
        relative = PurePosixPath(item)
        if relative.suffix.casefold() not in HEADER_SUFFIXES:
            continue
        if item in (exclude_paths or set()):
            continue
        if exclude_crypt and "crypt" in relative.parts[1:]:
            continue
        candidate = repository.joinpath(*relative.parts)
        if not candidate.is_file():
            raise RuntimeError(f"tracked public header is missing: {candidate}")
        headers.append(candidate)
    return sorted(headers, key=lambda item: item.as_posix().casefold())


def _header_license(path: Path) -> str:
    lines = path.read_text(encoding="utf-8-sig").splitlines()[:10]
    matches = {match for line in lines for match in SPDX_RE.findall(line)}
    if len(matches) != 1:
        raise RuntimeError(f"public header must declare one SPDX license in its first 10 lines: {path}")
    license_id = matches.pop()
    if license_id not in LICENSE_URLS:
        raise RuntimeError(f"unsupported public header SPDX license {license_id}: {path}")
    return license_id


def _relative(path: Path, repository: Path) -> str:
    return path.relative_to(repository).as_posix()


def _license_file(repository_id: str, repository: Path, source_path: str,
                  installed_name: str, license_id: str) -> dict[str, str]:
    source = repository / PurePosixPath(source_path)
    if not source.is_file():
        raise RuntimeError(f"required license file is missing: {source}")
    return {
        "repository": repository_id,
        "sourcePath": source_path,
        "installedPath": f"share/licenses/RinRuntime/{installed_name}",
        "license": license_id,
        "sha256": _sha256(source),
    }


def build_manifest(sdk_root: Path) -> dict[str, object]:
    sdk_root = sdk_root.resolve()
    sdk_revision = _git(sdk_root, "rev-parse", "HEAD")
    runtime_url = _git(ROOT, "remote", "get-url", "origin")
    sdk_url = _git(sdk_root, "remote", "get-url", "origin")

    lock = json.loads((ROOT / "dependencies.lock.json").read_text(encoding="utf-8"))
    sdk_dependency = lock.get("dependencies", {}).get("rinos-sdk", {})
    if sdk_dependency.get("revision") != sdk_revision:
        raise RuntimeError(
            "resolved RinOS-SDK revision does not match dependencies.lock.json: "
            f"{sdk_revision}")
    if sdk_dependency.get("url", "").removesuffix(".git").rstrip("/").casefold() != \
       sdk_url.removesuffix(".git").rstrip("/").casefold():
        raise RuntimeError("resolved RinOS-SDK origin does not match dependencies.lock.json")

    runtime_license = ROOT / "LICENSE"
    sdk_license = sdk_root / "LICENSE"
    gpl_license = sdk_root / "LICENSES" / "GPL-2.0-or-later.txt"
    runtime_license_id = _root_license(runtime_license)
    sdk_license_id = _root_license(sdk_license)
    if not gpl_license.is_file():
        raise RuntimeError(f"GPL terms are missing from RinOS-SDK: {gpl_license}")

    repositories = {
        "RinRuntime": {
            "url": runtime_url,
            "revision": "same commit as this manifest",
            "licenseFile": "LICENSE",
            "rootLicense": runtime_license_id,
        },
        "RinOS-SDK": {
            "url": sdk_url,
            "revision": sdk_revision,
            "licenseFile": "LICENSE",
            "rootLicense": sdk_license_id,
        },
    }

    headers = []
    runtime_public_roots = (
        ("include/rinruntime", True, RUNTIME_TARGET_ONLY_HEADERS),
        ("include/rincompression", False, set()),
    )
    for include_root, exclude_crypt, exclude_paths in runtime_public_roots:
        for path in _tracked_headers(ROOT, include_root, exclude_crypt,
                                     exclude_paths):
            source_path = _relative(path, ROOT)
            installed_path = "include/" + source_path.removeprefix("include/")
            headers.append({
                "repository": "RinRuntime",
                "sourcePath": source_path,
                "installedPath": installed_path,
                "license": _header_license(path),
                "licenseSource": "SPDX-License-Identifier",
            })
    for path in _tracked_headers(sdk_root, "include/rin"):
        source_path = _relative(path, sdk_root)
        headers.append({
            "repository": "RinOS-SDK",
            "sourcePath": source_path,
            "installedPath": "include/" + source_path.removeprefix("include/"),
            "license": _header_license(path),
            "licenseSource": "SPDX-License-Identifier",
        })
    headers.sort(key=lambda item: str(item["installedPath"]).casefold())

    license_files = [
        _license_file("RinRuntime", ROOT, "LICENSE",
                      "RinRuntime-MIT.txt", runtime_license_id),
        _license_file("RinOS-SDK", sdk_root, "LICENSE",
                      "RinOS-SDK-MIT.txt", sdk_license_id),
        _license_file("RinOS-SDK", sdk_root,
                      "LICENSES/GPL-2.0-or-later.txt",
                      "GPL-2.0-or-later.txt", "GPL-2.0-or-later"),
    ]

    return {
        "schemaVersion": 1,
        "scope": "First-party RinRuntime and RinOS-SDK public headers installed by RinRuntime.",
        "licenseGuide": "share/licenses/RinRuntime/LICENSE-README.md",
        "repositories": repositories,
        "licenseCatalog": {
            "MIT": {
                "spdxUrl": LICENSE_URLS["MIT"],
                "conditions": "Retain the copyright and permission notices in copies or substantial portions.",
            },
            "GPL-2.0-or-later": {
                "spdxUrl": LICENSE_URLS["GPL-2.0-or-later"],
                "conditions": "Retain notices and comply with the selected GPL version when distributing covered source or binaries.",
            },
        },
        "licenseFiles": license_files,
        "headers": headers,
    }


def _safe_installed_path(prefix: Path, relative: str) -> Path:
    path = PurePosixPath(relative)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise RuntimeError(f"manifest contains an unsafe installed path: {relative}")
    return prefix.joinpath(*path.parts)


def check_installed(prefix: Path) -> None:
    prefix = prefix.resolve()
    manifest_path = prefix / "share" / "licenses" / "RinRuntime" / MANIFEST.name
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    guide_path = _safe_installed_path(prefix, str(manifest["licenseGuide"]))
    if not guide_path.is_file():
        raise RuntimeError(f"installed public API license guide is missing: {guide_path}")
    expected_headers = {str(item["installedPath"]) for item in manifest["headers"]}
    actual_headers = set()
    for include_root in ("include/rin", "include/rinruntime", "include/rincompression"):
        root = prefix / PurePosixPath(include_root)
        if not root.is_dir():
            raise RuntimeError(f"installed public include directory is missing: {root}")
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.casefold() not in HEADER_SUFFIXES:
                continue
            if include_root == "include/rinruntime" and "crypt" in path.relative_to(root).parts:
                continue
            if include_root == "include/rinruntime" and \
                    path.relative_to(prefix).as_posix() in \
                    RUNTIME_TARGET_ONLY_HEADERS:
                continue
            actual_headers.add(path.relative_to(prefix).as_posix())
    if actual_headers != expected_headers:
        missing = sorted(expected_headers - actual_headers)
        extra = sorted(actual_headers - expected_headers)
        raise RuntimeError(
            f"installed first-party header inventory differs from manifest; "
            f"missing={missing}, extra={extra}")

    for item in manifest["licenseFiles"]:
        path = _safe_installed_path(prefix, str(item["installedPath"]))
        if not path.is_file():
            raise RuntimeError(f"installed license file is missing: {path}")
        if _sha256(path) != item["sha256"]:
            raise RuntimeError(f"installed license file hash does not match manifest: {path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-root", type=Path,
                        help="resolved RinOS-SDK source checkout")
    parser.add_argument("--installed-prefix", type=Path,
                        help="installed RinRuntime prefix to verify")
    parser.add_argument("--write", action="store_true",
                        help="regenerate the checked-in manifest")
    args = parser.parse_args(argv)

    if not args.sdk_root and not args.installed_prefix:
        parser.error("provide --sdk-root, --installed-prefix, or both")
    if args.write and (not args.sdk_root or args.installed_prefix):
        parser.error("--write requires --sdk-root and cannot be combined with --installed-prefix")

    try:
        if args.sdk_root:
            generated = build_manifest(args.sdk_root)
            serialized = json.dumps(generated, ensure_ascii=False,
                                    indent=2) + "\n"
            if args.write:
                MANIFEST.parent.mkdir(parents=True, exist_ok=True)
                MANIFEST.write_text(serialized, encoding="utf-8", newline="\n")
                print(f"wrote {MANIFEST}")
            else:
                current = json.loads(MANIFEST.read_text(encoding="utf-8"))
                if current != generated:
                    raise RuntimeError(
                        "public API license manifest is stale; regenerate it with --write")
                counts: dict[str, int] = {}
                for item in generated["headers"]:
                    license_id = str(item["license"])
                    counts[license_id] = counts.get(license_id, 0) + 1
                summary = ", ".join(
                    f"{count} {license_id}" for license_id, count in sorted(counts.items()))
                print(f"verified {len(generated['headers'])} public headers: {summary}")
        if args.installed_prefix:
            check_installed(args.installed_prefix)
            print("verified installed public headers and license files")
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError,
            KeyError, TypeError) as error:
        print(f"public API license manifest check failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
