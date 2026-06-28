from __future__ import annotations

import re
import statistics
from collections.abc import Iterable


BENCH_RE = re.compile(r"^\[BENCH_(?P<kind>[A-Z_]+)\]\s*(?P<body>.*)$")


def parse_bench_line(line: str) -> tuple[str, dict[str, str]] | None:
    match = BENCH_RE.match(line.strip())
    if not match:
        return None
    values: dict[str, str] = {}
    for token in match.group("body").split():
        if "=" in token:
            key, value = token.split("=", 1)
            values[key] = value
    return match.group("kind"), values


def number(values: dict[str, str], key: str) -> float | None:
    try:
        return float(values[key])
    except (KeyError, ValueError):
        return None


def percentile_95(values: list[float]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1)))))
    return ordered[index]


def aggregate(values: Iterable[float]) -> dict[str, str]:
    data = list(values)
    if not data:
        return {key: "" for key in ("mean", "median", "p95", "min", "max", "stddev")}
    return {
        "mean": f"{statistics.fmean(data):.3f}",
        "median": f"{statistics.median(data):.3f}",
        "p95": f"{percentile_95(data):.3f}",
        "min": f"{min(data):.3f}",
        "max": f"{max(data):.3f}",
        "stddev": f"{statistics.stdev(data) if len(data) > 1 else 0.0:.3f}",
    }

