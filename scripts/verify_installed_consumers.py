#!/usr/bin/env python3
"""Compile and run C11/C++20 consumers against an installed RinRuntime."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shlex
import subprocess
import sys


def run(command: list[str], *, env: dict[str, str] | None = None) -> None:
    print("+", shlex.join(command), flush=True)
    subprocess.run(command, check=True, env=env)


def pkg_config(*arguments: str, env: dict[str, str]) -> str:
    return subprocess.check_output(
        ["pkg-config", *arguments, "rinruntime"],
        text=True,
        env=env,
    ).strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--cc", default=os.environ.get("CC", "cc"))
    parser.add_argument("--cxx", default=os.environ.get("CXX", "c++"))
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()

    prefix = args.prefix.resolve()
    source_root = Path(__file__).resolve().parents[1] / "ci" / "consumer"
    pkg_files = sorted(prefix.rglob("rinruntime.pc"))
    if len(pkg_files) != 1:
        print(
            f"expected one installed rinruntime.pc, found {len(pkg_files)}",
            file=sys.stderr,
        )
        return 2
    env = os.environ.copy()
    old_pkg_path = env.get("PKG_CONFIG_PATH", "")
    pkg_path = str(pkg_files[0].parent)
    env["PKG_CONFIG_PATH"] = os.pathsep.join(
        part for part in (pkg_path, old_pkg_path) if part
    )
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    try:
        cflags = shlex.split(pkg_config("--cflags", env=env))
        libraries = shlex.split(pkg_config("--libs", env=env))
        libdir = Path(pkg_config("--variable=libdir", env=env)).resolve()
        cc = shlex.split(args.cc)
        cxx = shlex.split(args.cxx)
        if not cc or not cxx:
            raise ValueError("compiler command is empty")

        c_object = output_dir / "consumer-c.o"
        c_binary = output_dir / "consumer-c"
        cxx_binary = output_dir / "consumer-cxx"
        run(
            cc
            + ["-std=c11", *cflags, "-I", str(source_root), "-c",
               str(source_root / "consumer.c"), "-o", str(c_object)]
        )
        run(
            cxx
            + ["-std=c++20", *cflags, "-I", str(source_root),
               str(c_object), *libraries, f"-Wl,-rpath,{libdir}", "-o",
               str(c_binary)]
        )
        run([str(c_binary)])
        run(
            cxx
            + ["-std=c++20", *cflags, "-I", str(source_root),
               str(source_root / "consumer.cpp"), *libraries,
               f"-Wl,-rpath,{libdir}", "-o", str(cxx_binary)]
        )
        run([str(cxx_binary)])
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
