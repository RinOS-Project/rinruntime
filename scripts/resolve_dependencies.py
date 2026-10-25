#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Resolve RinRuntime's pinned source dependencies for CMake and Meson."""

from __future__ import annotations

import argparse
import errno
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

from prepare_i18n_header import prepare as prepare_i18n_header


_REVISION = re.compile(r"^[0-9a-f]{40}$")
_HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".inc"}


def _git(repository: Path, *arguments: str, check: bool = True) -> str:
    repository = repository.resolve()
    # Git expects safe.directory paths in normalized form on Windows.  A
    # backslash path can be treated as a different value on filesystems that
    # do not expose an ownership SID, causing even our newly-created cache to
    # be rejected as dubious.
    command = ["git", "-c", f"safe.directory={repository.as_posix()}",
               "-C", str(repository),
               *arguments]
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, check=False)
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"{' '.join(command)} failed: {detail}")
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def _has_worktree_artifacts(path: Path) -> bool:
    """Reject tracked edits, untracked files, and ignored cache injections."""
    if _git(path, "status", "--porcelain", "--untracked-files=all"):
        return True
    # `git status` intentionally hides ignored files. An ignored file can still
    # shadow a tracked include or source selected by a broad build include path,
    # so pinned dependency roots must not contain ignored working-tree data.
    return bool(_git(path, "ls-files", "-z", "--others", "--ignored",
                     "--exclude-standard", "--directory"))


def _is_clean_pinned_checkout(path: Path, dependency: dict[str, object]) -> bool:
    if not path.is_dir():
        return False
    try:
        top = Path(_git(path, "rev-parse", "--show-toplevel")).resolve()
        if top != path.resolve():
            return False
        if _git(path, "rev-parse", "HEAD") != dependency["revision"]:
            return False
        return not _has_worktree_artifacts(path)
    except (OSError, RuntimeError):
        return False


def _is_reparse_point(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    if stat.S_ISLNK(metadata.st_mode):
        return True
    # Windows junctions and other reparse points may not report S_ISLNK.
    return bool(getattr(metadata, "st_file_attributes", 0) & 0x400)


def _cache_path_under_root(path: Path, cache_root: Path) -> Path:
    """Reject cache paths that escape or redirect through a reparse point."""
    root = Path(os.path.abspath(cache_root))
    candidate = Path(os.path.abspath(path))
    try:
        relative = candidate.relative_to(root)
    except ValueError as error:
        raise RuntimeError(
            f"dependency cache path escapes its configured root: {candidate}") from error

    current = root
    for component in relative.parts:
        current /= component
        if _is_reparse_point(current):
            raise RuntimeError(
                f"dependency cache path contains a symlink or reparse point: {current}")

    resolved_root = root.resolve()
    resolved_candidate = candidate.resolve()
    try:
        resolved_candidate.relative_to(resolved_root)
    except ValueError as error:
        raise RuntimeError(
            f"dependency cache path resolves outside its configured root: {candidate}") from error
    return candidate


@contextmanager
def _dependency_cache_lock(path: Path, cache_root: Path):
    """Serialize initialization and validation of one pinned checkout."""
    path = _cache_path_under_root(path, cache_root)
    lock_path = _cache_path_under_root(
        path.with_name(path.name + ".lock"), cache_root)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = _cache_path_under_root(lock_path, cache_root)
    with lock_path.open("a+b") as lock_file:
        lock_file.seek(0, os.SEEK_END)
        if lock_file.tell() == 0:
            lock_file.write(b"\0")
            lock_file.flush()
        lock_file.seek(0)
        if os.name == "nt":
            import msvcrt

            retryable = {
                errno.EACCES,
                getattr(errno, "EAGAIN", errno.EACCES),
                getattr(errno, "EDEADLK", errno.EACCES),
            }
            while True:
                try:
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                    break
                except OSError as error:
                    if error.errno not in retryable:
                        raise
                    time.sleep(0.05)
            try:
                yield
            finally:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _ensure_cache_checkout(path: Path, dependency: dict[str, object],
                           cache_root: Path) -> Path:
    path = _cache_path_under_root(path, cache_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path = _cache_path_under_root(path, cache_root)
    with _dependency_cache_lock(path, cache_root):
        return _ensure_cache_checkout_locked(path, dependency, cache_root)


def _ensure_cache_checkout_locked(path: Path,
                                  dependency: dict[str, object],
                                  cache_root: Path) -> Path:
    path = _cache_path_under_root(path, cache_root)
    url = str(dependency["url"])
    revision = str(dependency["revision"])

    if path.exists():
        if not path.is_dir() or not (path / ".git").exists():
            raise RuntimeError(f"dependency cache path is occupied: {path}")
        origin = _git(path, "remote", "get-url", "origin", check=False)
        normalize = lambda value: value.removesuffix(".git").rstrip("/").casefold()
        if not origin:
            # Recover only the empty repository left by an interrupted cache
            # initialization.  Never adopt a populated repository without a
            # verifiable origin.
            current = _git(path, "rev-parse", "--verify", "HEAD", check=False)
            if current or _has_worktree_artifacts(path):
                raise RuntimeError(
                    "dependency cache has no verifiable origin or contains "
                    f"working-tree artifacts; preserve it manually: {path}")
            _git(path, "remote", "add", "origin", url)
            origin = url
        if normalize(origin) != normalize(url):
            raise RuntimeError(f"dependency cache has unexpected origin: {path}")
        if _has_worktree_artifacts(path):
            raise RuntimeError(
                "dependency cache contains tracked changes, untracked files, "
                f"or ignored artifacts; preserve and clear it manually: {path}")
    else:
        path.mkdir()
        path = _cache_path_under_root(path, cache_root)
        _git(path, "init")
        _git(path, "remote", "add", "origin", url)

    current = _git(path, "rev-parse", "HEAD", check=False)
    if current != revision:
        _git(path, "fetch", "--no-tags", "origin", revision)
        _git(path, "checkout", "--detach", revision)
    if _git(path, "rev-parse", "HEAD") != revision:
        raise RuntimeError(f"resolved dependency revision does not match lock: {path}")
    if _has_worktree_artifacts(path):
        raise RuntimeError(
            f"resolved dependency checkout contains working-tree artifacts: {path}")
    return _cache_path_under_root(path, cache_root).resolve()


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


def _dependency_cache_namespace(
        names: list[str], entries: dict[str, dict[str, object]]) -> str:
    identity = {
        name: {
            "url": str(entries[name].get("url", "")),
            "revision": str(entries[name].get("revision", "")),
        }
        for name in sorted(names)
    }
    canonical = json.dumps(identity, sort_keys=True,
                           separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


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
    if any(cache_name in ("", ".", "..")
           for cache_name in cache_names.values()) or \
       len(set(cache_names.values())) != len(cache_names):
        raise RuntimeError(
            "dependency checkout paths must have unique, non-special directory names")
    cache_namespace = _dependency_cache_namespace(names, entries)
    # Keep sibling-relative includes inside libi18n valid by choosing all local
    # checkouts together or resolving the complete dependency set in one cache.
    # Preserve each checkout's sibling name (for example RinOS-SDK and RinGPU)
    # because pinned headers may refer to another dependency by that path.
    use_local = all(_is_clean_pinned_checkout(local_roots[name], entries[name])
                    for name in names)
    if use_local:
        resolved = local_roots
    else:
        configured_cache = os.environ.get("RINRUNTIME_DEPENDENCY_CACHE_ROOT")
        cache_root = (Path(configured_cache).expanduser().resolve()
                      if configured_cache else build_root / "rinruntime-deps")
        cache_root.mkdir(parents=True, exist_ok=True)
        cache_root = cache_root.resolve()
        resolved = {
            name: _ensure_cache_checkout(
                cache_root / cache_namespace / cache_names[name], entries[name],
                cache_root)
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
                print(f"{header.resolve().as_posix()}|{install_path}")


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
            # Forward slashes are accepted by CMake and Meson on Windows and
            # keep generated install scripts from interpreting drive-letter
            # backslashes as CMake string escapes.
            print(resolved[name].as_posix())
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError,
            KeyError, TypeError) as error:
        print(f"rinruntime dependency resolution failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
