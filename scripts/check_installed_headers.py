#!/usr/bin/env python3
"""Compile every installed RinRuntime public header as an isolated include."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from pathlib import Path
import shlex
import subprocess
import sys


def compiler_words(value: str) -> list[str]:
    words = shlex.split(value)
    if not words:
        raise ValueError("compiler command is empty")
    return words


def header_jobs(include_root: Path) -> list[tuple[str, str, str]]:
    jobs: list[tuple[str, str, str]] = []
    for namespace in ("rinruntime", "rincompression"):
        directory = include_root / namespace
        if not directory.is_dir():
            raise FileNotFoundError(f"installed public include directory is missing: {directory}")
        for header in sorted(directory.rglob("*")):
            if not header.is_file() or header.suffix not in (".h", ".hpp"):
                continue
            include_name = header.relative_to(include_root).as_posix()
            if os.name == "nt" and include_name == "rinruntime/event_loop_poll.hpp":
                # This adapter is POSIX-only; its umbrella include is guarded
                # on Windows and the direct header requires poll(2).
                continue
            if header.suffix == ".hpp":
                jobs.append((include_name, "c++", "c++20"))
            else:
                jobs.append((include_name, "c", "c11"))
                jobs.append((include_name, "c++", "c++20"))
    return jobs


def compile_header(
    include_root: Path,
    include_name: str,
    language: str,
    standard: str,
    compiler: list[str],
) -> tuple[str, str, str | None]:
    source = f"#include <{include_name}>\nint main(void) {{ return 0; }}\n"
    command = compiler + [
        f"-std={standard}",
        "-fsyntax-only",
        "-x",
        language,
        "-I",
        str(include_root),
        "-",
    ]
    try:
        result = subprocess.run(
            command,
            input=source,
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        return include_name, language, str(error)
    if result.returncode == 0:
        return include_name, language, None
    detail = result.stderr.strip() or result.stdout.strip()
    return include_name, language, detail


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--cxx", default=os.environ.get("CXX", "c++"))
    parser.add_argument("--jobs", type=int, default=min(os.cpu_count() or 2, 8))
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error("--jobs must be positive")

    include_root = args.prefix.resolve() / "include"
    try:
        jobs = header_jobs(include_root)
        c_compiler = compiler_words(args.cc)
        cxx_compiler = compiler_words(args.cxx)
    except (FileNotFoundError, ValueError) as error:
        print(error, file=sys.stderr)
        return 2
    if not jobs:
        print("no installed public headers were found", file=sys.stderr)
        return 2

    failures: list[tuple[str, str, str]] = []
    with ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = [
            pool.submit(
                compile_header,
                include_root,
                include_name,
                language,
                standard,
                c_compiler if language == "c" else cxx_compiler,
            )
            for include_name, language, standard in jobs
        ]
        for future in as_completed(futures):
            include_name, language, error = future.result()
            if error is not None:
                failures.append((include_name, language, error))

    if failures:
        for include_name, language, error in sorted(failures):
            print(f"[{language}] <{include_name}> failed:\n{error}", file=sys.stderr)
        print(f"{len(failures)} of {len(jobs)} installed header modes failed", file=sys.stderr)
        return 1
    print(f"compiled {len(jobs)} isolated installed-header translation units")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
