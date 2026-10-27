#!/usr/bin/env python3
"""Contract tests for the standalone dependency checkout cache."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPT_DIR))
sys.dont_write_bytecode = True
import resolve_dependencies as resolver  # noqa: E402


def git(*arguments: str) -> str:
    result = subprocess.run(
        ["git", *arguments], check=True, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout.strip()


class DependencyResolverCacheTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory(
            prefix="rinruntime-dependency-cache-")
        self.root = Path(self.temporary_directory.name)
        self.remote = self.root / "origin.git"
        seed = self.root / "seed"
        git("init", "--bare", str(self.remote))
        git("init", "--initial-branch=main", str(seed))
        git("-C", str(seed), "config", "user.name", "RinRuntime contract test")
        git("-C", str(seed), "config", "user.email", "rinruntime-test@example.invalid")
        (seed / "include").mkdir()
        (seed / "include" / "pinned.h").write_text(
            "/* pinned fixture */\n", encoding="utf-8")
        (seed / ".gitignore").write_text("ignored.cache\n", encoding="utf-8")
        git("-C", str(seed), "add", ".")
        git("-C", str(seed), "commit", "-m", "fixture")
        git("-C", str(seed), "push", str(self.remote), "HEAD:refs/heads/main")
        self.revision = git("-C", str(seed), "rev-parse", "HEAD")
        self.cache_root = self.root / "cache"
        self.checkout = self.cache_root / "namespace" / "fixture"
        self.dependency = {
            "url": str(self.remote),
            "revision": self.revision,
        }

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def ensure_checkout(self) -> Path:
        return resolver._ensure_cache_checkout(
            self.checkout, self.dependency, self.cache_root)

    def test_concurrent_initialization_resolves_one_clean_pinned_checkout(self) -> None:
        with ThreadPoolExecutor(max_workers=4) as executor:
            resolved = list(executor.map(lambda _index: self.ensure_checkout(), range(4)))

        self.assertEqual(resolved, [self.checkout.resolve()] * 4)
        self.assertEqual(git("-C", str(self.checkout), "rev-parse", "HEAD"),
                         self.revision)
        self.assertEqual(
            git("-C", str(self.checkout), "status", "--porcelain",
                "--untracked-files=all"), "")
        self.assertTrue((self.checkout / "include" / "pinned.h").is_file())

    def test_ignored_worktree_artifacts_are_rejected(self) -> None:
        self.ensure_checkout()
        (self.checkout / "ignored.cache").write_text("shadow\n", encoding="utf-8")

        with self.assertRaisesRegex(RuntimeError, "ignored artifacts"):
            self.ensure_checkout()

    def test_cache_checkout_symlink_is_rejected(self) -> None:
        outside = self.root / "outside"
        outside.mkdir()
        self.checkout.parent.mkdir(parents=True)
        try:
            self.checkout.symlink_to(outside, target_is_directory=True)
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"directory symlinks are unavailable: {error}")

        with self.assertRaisesRegex(RuntimeError, "symlink or reparse point"):
            self.ensure_checkout()

    def test_hardlinked_lock_file_is_rejected(self) -> None:
        self.checkout.parent.mkdir(parents=True)
        external = self.root / "external.lock"
        external.write_bytes(b"\0")
        lock_path = self.checkout.with_name(self.checkout.name + ".lock")
        try:
            os.link(external, lock_path)
        except OSError as error:
            self.skipTest(f"hard links are unavailable: {error}")

        with self.assertRaisesRegex(RuntimeError, "private regular file"):
            self.ensure_checkout()


if __name__ == "__main__":
    unittest.main()
