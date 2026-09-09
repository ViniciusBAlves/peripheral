#!/usr/bin/env python3
"""Generate LaTeX tables comparing transfer cost across payload sizes."""

from __future__ import annotations

import argparse
import statistics
from collections import defaultdict
from pathlib import Path

from generate_transfer_energy_table import (
    load_transfer_attempts,
    payload_label,
    resolve_run_dir,
)
from plot_tls_handshake_bars import pki_category


PAYLOADS = (128, 1024, 8 * 1024, 16 * 1024, 32 * 1024, 64 * 1024)
PAYLOAD_GROUPS = (PAYLOADS[:3], PAYLOADS[3:])
PKI_KINDS = ("homogeneous", "heterogeneous")
DIRECTIONS = ("server_to_device", "device_to_server")

METRICS = (
    ("end_to_end_ms", "End-to-end time", "ms", 1.0, 2),
    ("transfer_avg_current_ua", "Average current", r"$\mu$A", 1.0, 2),
    ("transfer_energy_uj", "Energy", "mJ", 1000.0, 3),
    ("client_cpu_ms", "Active CPU time", "ms", 1.0, 2),
    ("client_cpu_usage_percent", "Average CPU usage", r"\%", 1.0, 2),
)


def number(value: str | None) -> float | None:
    try:
        return float(value) if value not in (None, "") else None
    except ValueError:
        return None


def variation(previous: float | None, current: float | None) -> str:
    if previous is None or current is None or previous == 0.0:
        return "--"
    return f"{(current / previous - 1.0) * 100.0:+.1f}\\%"


def aggregate(rows: list[dict[str, str]]) -> dict[tuple[str, str, int, str], float]:
    values: dict[tuple[str, str, int, str], list[float]] = defaultdict(list)
    metric_names = {metric[0] for metric in METRICS}
    for row in rows:
        pki = pki_category(row)
        direction = row.get("direction", "")
        payload = int(row.get("payload_bytes", "0"))
        if pki not in PKI_KINDS or direction not in DIRECTIONS or payload not in PAYLOADS:
            continue
        for metric in metric_names:
            value = number(row.get(metric))
            if value is not None:
                values[(pki, direction, payload, metric)].append(value)
    return {key: statistics.mean(group) for key, group in values.items()}


def table_block(
    means: dict[tuple[str, str, int, str], float],
    pki: str,
    direction: str,
    payloads: tuple[int, ...],
    previous_payload: int | None,
) -> list[str]:
    headers = ["Metric", "Unit"]
    previous = previous_payload
    for payload in payloads:
        headers.extend((
            payload_label(payload),
            "" if previous is None else (
                rf"$\Delta$ {payload_label(previous)}--{payload_label(payload)}"
            ),
        ))
        previous = payload

    lines = [
        r"\resizebox{\textwidth}{!}{%",
        r"\begin{tabular}{llrrrrrr}",
        r"\toprule",
        " & ".join(headers) + r" \\",
        r"\midrule",
    ]
    for metric, label, unit, divisor, decimals in METRICS:
        previous_raw = (
            means.get((pki, direction, previous_payload, metric))
            if previous_payload is not None
            else None
        )
        cells = [label, unit]
        for payload in payloads:
            raw = means.get((pki, direction, payload, metric))
            scaled = raw / divisor if raw is not None else None
            cells.extend((
                f"{scaled:.{decimals}f}" if scaled is not None else "--",
                variation(previous_raw, raw) if previous_raw is not None else "",
            ))
            previous_raw = raw
        lines.append(" & ".join(cells) + r" \\")
    lines.extend((r"\bottomrule", r"\end{tabular}%", r"}"))
    return lines


def generate(run_dir: Path, out_dir: Path) -> list[Path]:
    means = aggregate(load_transfer_attempts(run_dir))
    outputs: list[Path] = []
    out_dir.mkdir(parents=True, exist_ok=True)
    for pki in PKI_KINDS:
        for direction in DIRECTIONS:
            direction_label = (
                r"Server $\rightarrow$ device"
                if direction == "server_to_device"
                else r"Device $\rightarrow$ server"
            )
            lines = [
                r"% Requires \usepackage{booktabs,graphicx}",
                r"% Values are means across successful powered transfer attempts.",
                "",
                rf"\paragraph{{{pki.capitalize()} PKI, {direction_label}.}}",
            ]
            lines.extend(table_block(means, pki, direction, PAYLOAD_GROUPS[0], None))
            lines.extend(("", r"\par\medskip", ""))
            lines.extend(
                table_block(means, pki, direction, PAYLOAD_GROUPS[1], PAYLOADS[2])
            )
            output = out_dir / f"transfer_scaling_{pki}_{direction}.tex"
            output.write_text("\n".join(lines) + "\n", encoding="ascii")
            outputs.append(output)
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", help="transfer benchmark result directory or run id")
    parser.add_argument("--out-dir", type=Path, help="output directory")
    args = parser.parse_args()

    run_dir = resolve_run_dir(args.run_dir)
    out_dir = args.out_dir or (
        Path(__file__).resolve().parent / "out" / run_dir.name
    )
    outputs = generate(run_dir, out_dir.resolve())
    print(f"tables={len(outputs)}")
    for output in outputs:
        print(f"output={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
