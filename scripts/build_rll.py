#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Compile and sign a RinRuntime .rll from RinCompiler object inputs.

This is an explicit target-toolchain route.  It never substitutes a host
library or an unsigned placeholder: every source must compile with rcc and
rld must produce the signed output before it is atomically published.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rcc", required=True)
    parser.add_argument("--rld", required=True)
    parser.add_argument("--rinsign", required=True)
    parser.add_argument("--sign-key", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--sign-profile", choices=("debug", "release"),
                        required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--include", action="append", default=[])
    parser.add_argument("--source", action="append", required=True)
    parser.add_argument("--dependency", action="append", default=[])
    return parser


def _resolve_source(root: Path, value: str) -> Path:
    path = (root / value).resolve()
    if path != root and root not in path.parents:
        raise ValueError(f"source escapes source root: {value}")
    return path


def _resolve_path(root: Path, value: str) -> Path:
    return (root / value).resolve()


def _run(command: list[str]) -> None:
    print("+", " ".join(command))
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"command failed with status {result.returncode}")


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    root = args.source_root.resolve()
    output = args.output.resolve()
    sources = [_resolve_source(root, item) for item in args.source]
    includes = [_resolve_path(root, item) for item in args.include]
    dependencies = [_resolve_path(root, item) for item in args.dependency]

    if not root.is_dir():
        raise ValueError(f"source root is not a directory: {root}")
    if not sources or any(not path.is_file() for path in sources):
        missing = [str(path) for path in sources if not path.is_file()]
        raise ValueError("missing RinRuntime source: " + ", ".join(missing))
    if any(not path.is_dir() for path in includes):
        missing = [str(path) for path in includes if not path.is_dir()]
        raise ValueError("missing RinRuntime include directory: " +
                         ", ".join(missing))
    if any(not path.is_file() for path in dependencies):
        missing = [str(path) for path in dependencies if not path.is_file()]
        raise ValueError("missing RinRuntime dependency: " + ", ".join(missing))
    if not output.parent.is_dir():
        raise ValueError(f"output directory does not exist: {output.parent}")

    include_args: list[str] = []
    for include in includes:
        include_args.extend(("-I", str(include)))

    try:
        with tempfile.TemporaryDirectory(
                prefix=".rinruntime-rll-", dir=str(output.parent)) as temporary:
            object_paths: list[Path] = []
            for index, source in enumerate(sources):
                object_path = Path(temporary) / f"source-{index:04d}.ro"
                _run([
                    args.rcc,
                    "-c",
                    "--target", args.target,
                    "-ffreestanding",
                    "-fPIC",
                    "-O2",
                    "-DRIN_FREESTANDING=1",
                    "-DRIN_USERSPACE=1",
                    *include_args,
                    str(source),
                    "-o", str(object_path),
                ])
                if not object_path.is_file():
                    raise RuntimeError(f"rcc did not produce {object_path}")
                object_paths.append(object_path)

            unsigned = Path(temporary) / "RinRuntime-unsigned.rll"
            rld_command = [
                args.rld,
                "--shared",
                "--target", args.target,
                "-o", str(unsigned),
                "--rinsign", args.rinsign,
                "--sign-key", args.sign_key,
                "--public-key", args.public_key,
                "--sign-profile", args.sign_profile,
            ]
            for dependency in dependencies:
                rld_command.extend(("--dep", str(dependency)))
            rld_command.extend(str(path) for path in object_paths)
            _run(rld_command)
            if not unsigned.is_file() or unsigned.stat().st_size == 0:
                raise RuntimeError("rld did not produce a signed RinRuntime image")
            os.replace(unsigned, output)
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: RinRuntime .rll route failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
