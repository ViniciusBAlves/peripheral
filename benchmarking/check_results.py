#!/usr/bin/env python3
"""Report whether every recorded execution succeeded for each benchmark case."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"


def resolve_run_dir(value: str) -> Path:
    path = Path(value).expanduser()
    if path.is_dir():
        return path.resolve()
    candidate = RESULTS / value
    if candidate.is_dir():
        return candidate.resolve()
    raise FileNotFoundError(f"benchmark results directory not found: {value}")


def expected_case_ids(run_dir: Path) -> list[str]:
    manifest = run_dir / "run_manifest.csv"
    if not manifest.exists():
        return []
    with manifest.open(newline="") as stream:
        return [
            row["case_id"]
            for row in csv.DictReader(stream)
            if row.get("case_id")
        ]


def attempts_by_case(run_dir: Path) -> dict[str, list[dict[str, str]]]:
    result: dict[str, list[dict[str, str]]] = {}
    for attempts_csv in sorted((run_dir / "cases").glob("*/attempts.csv")):
        with attempts_csv.open(newline="") as stream:
            rows = list(csv.DictReader(stream))
        case_id = (
            rows[0].get("case_id", "") if rows else ""
        ) or attempts_csv.parent.name.split("_", 1)[-1]
        result[case_id] = rows
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Print PASS only when every execution of a case succeeded."
    )
    parser.add_argument(
        "run_dir",
        help="result directory or run id under benchmarking/results",
    )
    parser.add_argument(
        "--ongoing",
        action="store_true",
        help="hide cases that do not have any recorded attempts yet",
    )
    args = parser.parse_args()
    run_dir = resolve_run_dir(args.run_dir)
    attempts = attempts_by_case(run_dir)
    case_ids = expected_case_ids(run_dir) or sorted(attempts)
    failed = False

    for case_id in case_ids:
        rows = attempts.get(case_id, [])
        if args.ongoing and not rows:
            continue
        successes = sum(row.get("status") == "success" for row in rows)
        if rows and successes == len(rows):
            print(f"PASS {case_id} ({successes}/{len(rows)})")
        else:
            failed = True
            status_counts: dict[str, int] = {}
            for row in rows:
                status = row.get("status") or "missing_status"
                status_counts[status] = status_counts.get(status, 0) + 1
            detail = ",".join(
                f"{status}={count}"
                for status, count in sorted(status_counts.items())
            ) or "no_attempts"
            print(
                f"FAIL {case_id} ({successes}/{len(rows)}; {detail})"
            )

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
