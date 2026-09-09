#!/usr/bin/env python3
"""Report or remove legacy benchmark build trees without touching results."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parent
TARGETS = (
    ROOT / "work" / "firmware-build",
    ROOT / "work" / "generated",
)


def directory_size(path: Path) -> int:
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def human_size(value: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}"
        value /= 1024
    raise AssertionError("unreachable")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--apply", action="store_true",
        help="delete the reported legacy caches (default: report only)",
    )
    args = parser.parse_args()

    total = 0
    for target in TARGETS:
        size = directory_size(target) if target.exists() else 0
        total += size
        print(f"{human_size(size):>10}  {target}")
        if args.apply and target.exists():
            shutil.rmtree(target)

    action = "removed" if args.apply else "reclaimable"
    print(f"{action}: {human_size(total)}")
    print(f"results preserved: {ROOT / 'results'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
