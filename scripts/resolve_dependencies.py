#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Resolve RinRuntime's pinned source dependencies for CMake and Meson."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from prepare_i18n_header import prepare as prepare_i18n_header


_REVISION = re.compile(r"^[0-9a-f]{40}$")
_HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".inc"}


def _git(repository: Path, *arguments: str, check: bool = True) -> str:
    command = ["git", "-c", f"safe.directory={repository}", "-C", str(repository),
               *arguments]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{' '.join(command)} failed: {detail}")
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def _is_clean_pinned_checkout(path: Path, dependency: dict[str, object]) -> bool:
    if not path.is_dir():
        return False
    try:
        top = Path(_git(path, "rev-parse", "--show-toplevel")).resolve()
        if top != path.resolve():
            return False
        if _git(path, "rev-parse", "HEAD") != dependency["revision"]:
            return False
        return not _git(path, "status", "--porcelain", "--untracked-files=all")
    except (OSError, RuntimeError):
        return False


def _ensure_cache_checkout(path: Path, dependency: dict[str, object]) -> Path:
    url = str(dependency["url"])
    revision = str(dependency["revision"])
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        if not path.is_dir() or not (path / ".git").exists():
            raise RuntimeError(f"dependency cache path is occupied: {path}")
        origin = _git(path, "remote", "get-url", "origin", check=False)
        normalize = lambda value: value.removesuffix(".git").rstrip("/").casefold()
        if not origin or normalize(origin) != normalize(url):
            raise RuntimeError(f"dependency cache has unexpected origin: {path}")
        if _git(path, "status", "--porcelain", "--untracked-files=all"):
            raise RuntimeError(f"dependency cache has local changes; preserve and clear it manually: {path}")
    else:
        path.mkdir()
        _git(path, "init")
        _git(path, "remote", "add", "origin", url)

    current = _git(path, "rev-parse", "HEAD", check=False)
    if current != revision:
        _git(path, "fetch", "--no-tags", "origin", revision)
        _git(path, "checkout", "--detach", revision)
    if _git(path, "rev-parse", "HEAD") != revision:
        raise RuntimeError(f"resolved dependency revision does not match lock: {path}")
    if _git(path, "status", "--porcelain", "--untracked-files=all"):
        raise RuntimeError(f"resolved dependency checkout is not clean: {path}")
    return path.resolve()


def _validate_required_paths(name: str, root: Path,
                             dependency: dict[str, object]) -> None:
    missing = [str(item) for item in dependency.get("requiredPaths", [])
               if not (root / str(item)).is_file()]
    if missing:
        raise RuntimeError(f"{name} at {root} is missing locked paths: " +
                           ", ".join(missing))


def _verify_core_dependency_pins(source_root: Path, names: list[str],
                                entries: dict[str, dict[str, object]]) -> None:
    if len(source_root.parents) < 3:
        return
    core_root = source_root.parents[2]
    expected_runtime = core_root / "public-base" / "libs" / "rinruntime"
    if not expected_runtime.is_dir() or expected_runtime.resolve() != source_root.resolve():
        return
    if not (core_root / ".git").exists():
        return
    for name in names:
        core_path = entries[name].get("corePath")
        if not isinstance(core_path, str) or not core_path:
            raise RuntimeError(f"{name} has no Core gitlink path in the lock manifest")
        tree_entry = _git(core_root, "ls-tree", "HEAD", "--", core_path)
        fields = tree_entry.split()
        if len(fields) < 3 or fields[0] != "160000" or fields[1] != "commit":
            raise RuntimeError(f"Core does not contain the expected dependency gitlink: {core_path}")
        if fields[2] != entries[name]["revision"]:
            raise RuntimeError(
                f"Core gitlink {core_path} is {fields[2]}, but dependencies.lock.json pins "
                f"{name} to {entries[name]['revision']}")


def _resolve(source_root: Path, build_root: Path, names: list[str],
             manifest_path: Path) -> dict[str, Path]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schemaVersion") != 1:
        raise RuntimeError("unsupported dependencies.lock.json schemaVersion")
    entries: dict[str, dict[str, object]] = manifest.get("dependencies", {})
    for name in names:
        if name not in entries:
            raise RuntimeError(f"dependency is not pinned in manifest: {name}")
        entry = entries[name]
        if not _REVISION.fullmatch(str(entry.get("revision", ""))):
            raise RuntimeError(f"{name} must use a full 40-character commit ID")
        if not str(entry.get("url", "")).startswith("https://"):
            raise RuntimeError(f"{name} must use an HTTPS repository URL")
    _verify_core_dependency_pins(source_root, names, entries)

    local_roots = {
        name: (source_root / str(entries[name]["checkout"])).resolve()
        for name in names
    }
    cache_names = {
        name: Path(str(entries[name]["checkout"])).name
        for name in names
    }
    if any(not cache_name for cache_name in cache_names.values()) or \
       len(set(cache_names.values())) != len(cache_names):
        raise RuntimeError("dependency checkout paths must have unique directory names")
    # Keep sibling-relative includes inside libi18n valid by choosing all local
    # checkouts together or resolving the complete dependency set in one cache.
    # Preserve each checkout's sibling name (for example RinOS-SDK and RinGPU)
    # because pinned headers may refer to another dependency by that path.
    use_local = all(_is_clean_pinned_checkout(local_roots[name], entries[name])
                    for name in names)
    if use_local:
        resolved = local_roots
    else:
        cache_root = build_root / "rinruntime-deps"
        resolved = {
            name: _ensure_cache_checkout(cache_root / cache_names[name], entries[name])
            for name in names
        }

    for name, root in resolved.items():
        _validate_required_paths(name, root, entries[name])
    return resolved


def _print_public_headers(header_roots: list[str]) -> None:
    for item in header_roots:
        source, separator, install_subdir = item.partition("=")
        if not separator or not source or not install_subdir:
            raise RuntimeError("header roots use the form SOURCE=INSTALL_SUBDIR")
        source_root = Path(source).resolve()
        if not source_root.is_dir():
            raise RuntimeError(f"public include directory does not exist: {source_root}")
        for header in sorted(source_root.rglob("*")):
            if header.is_file() and header.suffix.casefold() in _HEADER_SUFFIXES:
                relative = header.relative_to(source_root).as_posix()
                install_path = "/".join(part for part in
                                         (install_subdir.strip("/"),
                                          str(Path(relative).parent).replace("\\", "/"))
                                         if part not in ("", "."))
                print(f"{header.resolve()}|{install_path}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path)
    parser.add_argument("--build-root", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--dependency", action="append", default=[])
    parser.add_argument("--header-root", action="append", default=[])
    parser.add_argument("--list-public-headers", action="store_true")
    parser.add_argument("--skip-i18n-header", action="store_true")
    args = parser.parse_args(argv)

    try:
        if args.list_public_headers:
            _print_public_headers(args.header_root)
            return 0
        if not args.source_root or not args.build_root or not args.dependency:
            parser.error("dependency resolution requires --source-root, --build-root, and --dependency")
        source_root = args.source_root.resolve()
        build_root = args.build_root.resolve()
        manifest_path = (args.manifest or source_root / "dependencies.lock.json").resolve()
        resolved = _resolve(source_root, build_root, args.dependency, manifest_path)
        if "libi18n" in resolved and not args.skip_i18n_header:
            prepare_i18n_header(resolved["libi18n"] / "rin_i18n.h",
                                build_root / "rin_i18n.h")
        for name in args.dependency:
            print(resolved[name])
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError,
            KeyError, TypeError) as error:
        print(f"rinruntime dependency resolution failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
