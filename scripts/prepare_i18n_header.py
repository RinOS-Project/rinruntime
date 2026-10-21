#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Relocate libi18n's pinned public resource include for package installs."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def prepare(source: Path, destination: Path) -> None:
    old = '#include "../rinresource/include/rinresource/loader.h"'
    new = "#include <rinresource/loader.h>"
    contents = source.read_text(encoding="utf-8")
    if contents.count(old) != 1:
        raise ValueError("pinned rin_i18n.h no longer has the expected resource include")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(contents.replace(old, new), encoding="utf-8",
                           newline="\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        prepare(args.input, args.output)
    except (OSError, ValueError) as error:
        print(f"rinruntime i18n header preparation failed: {error}",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
