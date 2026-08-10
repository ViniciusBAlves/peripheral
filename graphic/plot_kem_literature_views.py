#!/usr/bin/env python3
"""Create literature-inspired plots for the nRF52840 KEM benchmark."""

from __future__ import annotations

import argparse
import csv
import math
import sys
import textwrap
from pathlib import Path

try:
    import matplotlib.pyplot as plt
    import numpy as np
except ImportError as exc:  # pragma: no cover - depends on local environment
    raise SystemExit(
        "Missing Python plotting dependency. Install matplotlib and numpy with:\n"
        "  python -m pip install matplotlib numpy"
    ) from exc


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "benchmarking" / "results"
sys.path.insert(0, str(ROOT / "benchmarking"))

from benchmarklib.algorithms import KEMS_BY_NAME  # noqa: E402


REFERENCES = (
    {
        "short": "pqm4",
        "title": "Kannwischer et al., pqm4: Testing and Benchmarking NIST PQC on ARM Cortex-M4",
        "url": "https://eprint.iacr.org/2019/844",
        "used_for": "operation timing/cycles and memory pressure on Cortex-M4",
    },
    {
        "short": "SUPERCOP/eBACS",
        "title": "Bernstein and Lange, eBACS/SUPERCOP benchmarking framework",
        "url": "https://bench.cr.yp.to/supercop.html",
        "used_for": "per-primitive operation comparisons and normalized efficiency",
    },
    {
        "short": "PQ TLS embedded",
        "title": "Tasopoulos et al., Performance Evaluation of PQ TLS 1.3 on Resource-Constrained Embedded Systems",
        "url": "https://eprint.iacr.org/2021/1553",
        "used_for": "time, memory, and bandwidth/traffic views for constrained devices",
    },
    {
        "short": "KEMTLS embedded",
        "title": "Gonzalez and Wiggers, KEMTLS vs. Post-Quantum TLS on Embedded Systems",
        "url": "https://kemtls.org/publication/kemtls-embedded/",
        "used_for": "runtime, memory, traffic volume, and code-size tradeoff framing",
    },
)

FAMILY_COLORS = {
    "classic": "#475569",
    "pqc": "#0f766e",
    "hybrid": "#7c3aed",
}

SECURITY_MARKERS = {
    "L1": "o",
    "L3": "s",
    "L5": "^",
    "?": "D",
}

OPERATION_COLORS = {
    "Keygen": "#2563eb",
    "Encapsulation": "#0f766e",
    "Decapsulation": "#dc2626",
}

CLASSIC_BASELINES = {
    "L1": "ECDHE-P-256",
    "L3": "ECDHE-P-384",
    "L5": "ECDHE-P-521",
}


def resolve_run_dir(value: str) -> Path:
    path = Path(value).expanduser()
    if path.is_dir():
        return path.resolve()
    candidate = RESULTS / value
    if candidate.is_dir():
        return candidate.resolve()
    raise FileNotFoundError(f"KEM benchmark result directory not found: {value}")


def number(row: dict[str, str], field: str) -> float | None:
    value = row.get(field, "")
    if value == "":
        return None
    try:
        result = float(value)
    except ValueError:
        return None
    return result if math.isfinite(result) else None


def load_rows(run_dir: Path) -> list[dict[str, str]]:
    summary = run_dir / "summary.csv"
    if not summary.exists():
        raise FileNotFoundError(f"summary.csv not found in {run_dir}")
    with summary.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    rows = [
        row for row in rows
        if row.get("success_count", "0") not in {"", "0"}
        and number(row, "mean_kem_total_ms") is not None
    ]
    if not rows:
        raise ValueError(f"no successful KEM rows found in {summary}")
    return sorted(rows, key=sort_key)


def kem_family(row: dict[str, str]) -> str:
    name = row.get("kex_group", "")
    if "MLKEM" in name and not name.startswith("MLKEM"):
        return "hybrid"
    known = KEMS_BY_NAME.get(name)
    return row.get("kex_family") or (known.family if known is not None else "unknown")


def security_level(row: dict[str, str]) -> str:
    try:
        level = int(float(row.get("kex_nist_level", "")))
    except ValueError:
        return "?"
    if level <= 2:
        return "L1"
    if level <= 3:
        return "L3"
    return "L5"


def row_label(row: dict[str, str]) -> str:
    return f"{security_level(row)} {row.get('kex_group', '')}"


def sort_key(row: dict[str, str]) -> tuple[int, int, int, str]:
    name = row.get("kex_group", "")
    family_rank = 0 if name.startswith("ECDHE") else 1 if name.startswith("MLKEM") else 2
    kem = KEMS_BY_NAME.get(name)
    level = kem.nist_level if kem is not None else int(number(row, "kex_nist_level") or 99)
    order = list(KEMS_BY_NAME).index(name) if name in KEMS_BY_NAME else 99
    return family_rank, level, order, name


def exchanged_bytes(row: dict[str, str]) -> float:
    return sum(
        number(row, field) or 0.0
        for field in (
            "kex_public_key_bytes",
            "kex_ciphertext_bytes",
            "kex_shared_secret_bytes",
        )
    )


def transmitted_bytes(row: dict[str, str]) -> float:
    return sum(
        number(row, field) or 0.0
        for field in ("kex_public_key_bytes", "kex_ciphertext_bytes")
    )


def heap_percent(row: dict[str, str]) -> float:
    direct = number(row, "max_client_heap_peak_usage_percent")
    if direct is not None:
        return direct
    peak = number(row, "max_client_heap_peak_bytes")
    capacity = number(row, "client_heap_capacity_bytes")
    if peak is None or capacity is None or capacity <= 0:
        return 0.0
    return 100.0 * peak / capacity


def positive(values: list[float]) -> list[float]:
    return [value for value in values if value > 0 and math.isfinite(value)]


def save(fig, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    print(output)


def add_source_note(fig, sources: list[str]) -> None:
    text = "Inspired by: " + "; ".join(sources)
    fig.text(
        0.01, 0.01, textwrap.fill(text, width=150),
        ha="left", va="bottom", fontsize=7, color="#334155",
    )


def add_family_legend(ax, loc: str = "upper right") -> None:
    handles = [
        plt.Line2D(
            [0], [0], marker="s", color="w", markerfacecolor=color,
            markersize=9, label=name.title(),
        )
        for name, color in FAMILY_COLORS.items()
    ]
    ax.legend(handles=handles, loc=loc, frameon=True, fontsize=8)


def set_log_axis(ax, values: list[float]) -> None:
    vals = positive(values)
    if not vals:
        return
    ax.set_xscale("log")
    ax.set_xlim(left=max(min(vals) * 0.65, 0.001), right=max(vals) * 1.8)


def annotate_horizontal(ax, bars, values: list[float], fmt: str = "{:.2f}") -> None:
    for bar, value in zip(bars, values):
        if value <= 0:
            continue
        ax.text(
            bar.get_width(), bar.get_y() + bar.get_height() / 2,
            " " + fmt.format(value), va="center", ha="left", fontsize=8,
        )


def plot_operation_costs(rows: list[dict[str, str]], output: Path, run_id: str) -> None:
    fields = (
        ("mean_kem_keygen_ms", "p95_kem_keygen_ms", "Keygen"),
        ("mean_kem_encapsulation_ms", "p95_kem_encapsulation_ms", "Encapsulation"),
        ("mean_kem_decapsulation_ms", "p95_kem_decapsulation_ms", "Decapsulation"),
    )
    y = np.arange(len(rows))
    height = 0.24
    all_values: list[float] = []
    fig, ax = plt.subplots(
        figsize=(12.5, max(5.8, len(rows) * 0.58)), constrained_layout=True
    )
    for offset, (mean_field, p95_field, name) in zip((-height, 0.0, height), fields):
        means = [number(row, mean_field) or 0.0 for row in rows]
        p95s = [number(row, p95_field) or mean for row, mean in zip(rows, means)]
        all_values.extend(means + p95s)
        ax.barh(
            y + offset, means, height=height,
            color=OPERATION_COLORS[name], edgecolor="#111827",
            linewidth=0.3, label=f"{name} mean",
        )
        ax.scatter(
            p95s, y + offset, marker="|", s=95, color="#111827",
            label=f"{name} p95" if offset == -height else None,
            zorder=3,
        )
    ax.set_title(f"Per-operation KEM cost - {run_id}")
    ax.set_xlabel("Time (ms, log scale); vertical tick is p95")
    ax.set_yticks(y)
    ax.set_yticklabels([row_label(row) for row in rows], fontsize=8)
    ax.grid(axis="x", color="#e5e7eb", linewidth=0.8)
    ax.legend(loc="lower right", fontsize=8)
    set_log_axis(ax, all_values)
    add_source_note(fig, ["SUPERCOP/eBACS per-operation benchmarking", "pqm4 Cortex-M4 operation timing"])
    save(fig, output)


def plot_resource_tradeoff(
    rows: list[dict[str, str]], output: Path, run_id: str
) -> None:
    fig, ax = plt.subplots(figsize=(11, 7.5), constrained_layout=True)
    max_heap = max((number(row, "max_client_heap_peak_bytes") or 1.0) for row in rows)
    offsets = [(6, 5), (6, -10), (-4, 8), (-6, -12)]
    for index, row in enumerate(rows):
        x = transmitted_bytes(row)
        y = number(row, "mean_kem_total_ms") or 0.0
        heap = number(row, "max_client_heap_peak_bytes") or 0.0
        size = 70.0 + 260.0 * heap / max_heap
        level = security_level(row)
        ax.scatter(
            x, y, s=size, marker=SECURITY_MARKERS.get(level, "D"),
            color=FAMILY_COLORS.get(kem_family(row), "#64748b"),
            edgecolor="#111827", linewidth=0.5, alpha=0.84,
        )
        ax.annotate(
            row_label(row), (x, y), xytext=offsets[index % len(offsets)],
            textcoords="offset points", fontsize=8,
            ha="left" if offsets[index % len(offsets)][0] >= 0 else "right",
        )
    ax.set_title(f"Runtime, memory, and traffic tradeoff - {run_id}")
    ax.set_xlabel("Public key + ciphertext bytes")
    ax.set_ylabel("Mean total KEM time (ms, log scale)")
    if positive([transmitted_bytes(row) for row in rows]):
        ax.set_xscale("log")
    if positive([number(row, "mean_kem_total_ms") or 0.0 for row in rows]):
        ax.set_yscale("log")
    ax.grid(True, color="#e5e7eb", linewidth=0.8)
    add_family_legend(ax, loc="lower right")
    add_source_note(fig, ["PQ TLS embedded time/memory/bandwidth evaluation", "KEMTLS embedded runtime/memory/traffic framing"])
    save(fig, output)


def plot_normalized_overhead(
    rows: list[dict[str, str]], output: Path, run_id: str
) -> None:
    by_name = {row.get("kex_group", ""): row for row in rows}
    rows_with_baseline = [
        row for row in rows
        if CLASSIC_BASELINES.get(security_level(row)) in by_name
    ]
    if not rows_with_baseline:
        print("warning: no same-security ECDHE baselines found for normalized overhead")
        return
    metrics = (
        ("mean_kem_total_ms", "Time"),
        ("_transmitted_bytes", "Bytes"),
        ("max_client_heap_peak_bytes", "Heap"),
    )
    y = np.arange(len(rows_with_baseline))
    width = 0.24
    fig, ax = plt.subplots(
        figsize=(12, max(5.8, len(rows_with_baseline) * 0.58)),
        constrained_layout=True,
    )
    all_values: list[float] = []
    for offset, (field, name) in zip((-width, 0.0, width), metrics):
        values = []
        for row in rows_with_baseline:
            baseline = by_name[CLASSIC_BASELINES[security_level(row)]]
            current_value = (
                transmitted_bytes(row) if field == "_transmitted_bytes"
                else number(row, field) or 0.0
            )
            baseline_value = (
                transmitted_bytes(baseline) if field == "_transmitted_bytes"
                else number(baseline, field) or 0.0
            )
            values.append(current_value / baseline_value if baseline_value > 0 else 0.0)
        all_values.extend(values)
        bars = ax.barh(
            y + offset, values, height=width,
            color={"Time": "#2563eb", "Bytes": "#0f766e", "Heap": "#f97316"}[name],
            edgecolor="#111827", linewidth=0.3, label=name,
        )
        if len(rows_with_baseline) <= 12:
            annotate_horizontal(ax, bars, values, "{:.2f}x")
    ax.axvline(1.0, color="#111827", linewidth=0.8, linestyle="--")
    ax.set_title(f"Normalized KEM overhead vs same-security ECDHE - {run_id}")
    ax.set_xlabel("Multiple of same-level ECDHE baseline (log scale)")
    ax.set_yticks(y)
    ax.set_yticklabels([row_label(row) for row in rows_with_baseline], fontsize=8)
    ax.grid(axis="x", color="#e5e7eb", linewidth=0.8)
    ax.legend(loc="lower right")
    set_log_axis(ax, all_values)
    add_source_note(fig, ["PQ TLS embedded classical/PQC comparison", "KEMTLS embedded runtime and traffic comparison"])
    save(fig, output)


def plot_efficiency(rows: list[dict[str, str]], output: Path, run_id: str) -> None:
    labels = [row_label(row) for row in rows]
    byte_efficiency = [
        (number(row, "mean_kem_total_ms") or 0.0) / max(transmitted_bytes(row), 1.0)
        for row in rows
    ]
    cycle_efficiency = [
        (number(row, "mean_dwt_cyccnt") or 0.0) / max(exchanged_bytes(row), 1.0)
        for row in rows
    ]
    y = np.arange(len(rows))
    fig, axes = plt.subplots(
        1, 2, figsize=(14, max(5.8, len(rows) * 0.55)),
        constrained_layout=True,
    )
    bars = axes[0].barh(
        y, byte_efficiency, color=[FAMILY_COLORS.get(kem_family(row), "#64748b") for row in rows],
        edgecolor="#111827", linewidth=0.35,
    )
    axes[0].set_title("Time per transmitted byte")
    axes[0].set_xlabel("ms / byte (log scale)")
    axes[0].set_yticks(y)
    axes[0].set_yticklabels(labels, fontsize=8)
    axes[0].grid(axis="x", color="#e5e7eb", linewidth=0.8)
    set_log_axis(axes[0], byte_efficiency)
    annotate_horizontal(axes[0], bars, byte_efficiency, "{:.4f}")

    if any(value > 0 for value in cycle_efficiency):
        bars = axes[1].barh(
            y, cycle_efficiency,
            color=[FAMILY_COLORS.get(kem_family(row), "#64748b") for row in rows],
            edgecolor="#111827", linewidth=0.35,
        )
        axes[1].set_title("Cycles per exchanged byte")
        axes[1].set_xlabel("DWT cycles / byte (log scale)")
        set_log_axis(axes[1], cycle_efficiency)
        annotate_horizontal(axes[1], bars, cycle_efficiency, "{:.1f}")
    else:
        axes[1].text(0.5, 0.5, "No DWT cycle data", ha="center", va="center")
        axes[1].set_axis_off()
    axes[1].set_yticks(y)
    axes[1].set_yticklabels([])
    axes[1].grid(axis="x", color="#e5e7eb", linewidth=0.8)
    fig.suptitle(f"Normalized KEM efficiency - {run_id}", fontsize=14)
    add_source_note(fig, ["SUPERCOP/eBACS normalized primitive efficiency", "pqm4 cycle-count benchmarking"])
    save(fig, output)


def plot_memory_budget(rows: list[dict[str, str]], output: Path, run_id: str) -> None:
    y = np.arange(len(rows))
    labels = [row_label(row) for row in rows]
    heap = [heap_percent(row) for row in rows]
    static_ram = [number(row, "firmware_static_ram_usage_percent") or 0.0 for row in rows]
    fig, axes = plt.subplots(
        1, 2, figsize=(14, max(5.8, len(rows) * 0.55)),
        constrained_layout=True,
    )
    for ax, values, title in (
        (axes[0], heap, "Peak benchmark heap"),
        (axes[1], static_ram, "Static firmware RAM image"),
    ):
        bars = ax.barh(
            y, values, color=[FAMILY_COLORS.get(kem_family(row), "#64748b") for row in rows],
            edgecolor="#111827", linewidth=0.35,
        )
        ax.set_title(title)
        ax.set_xlabel("Percent of configured budget")
        ax.set_xlim(0, max(100.0, max(values) * 1.15 if values else 100.0))
        ax.grid(axis="x", color="#e5e7eb", linewidth=0.8)
        annotate_horizontal(ax, bars, values, "{:.2f}%")
    axes[0].set_yticks(y)
    axes[0].set_yticklabels(labels, fontsize=8)
    axes[1].set_yticks(y)
    axes[1].set_yticklabels([])
    fig.suptitle(f"KEM memory budget pressure - {run_id}", fontsize=14)
    add_source_note(fig, ["pqm4 embedded suitability and memory pressure", "PQ TLS embedded memory evaluation"])
    save(fig, output)


def plot_dwt_density(rows: list[dict[str, str]], output: Path, run_id: str) -> None:
    event_fields = (
        ("mean_dwt_cpicnt", "CPICNT"),
        ("mean_dwt_lsucnt", "LSUCNT"),
        ("mean_dwt_exccnt", "EXCCNT"),
        ("mean_dwt_sleepcnt", "SLEEPCNT"),
        ("mean_dwt_foldcnt", "FOLDCNT"),
    )
    if not any((number(row, field) or 0.0) > 0 for row in rows for field, _ in event_fields):
        print("warning: no DWT event counter data found")
        return
    cycles = [number(row, "mean_dwt_cyccnt") or 0.0 for row in rows]
    labels = [row_label(row) for row in rows]
    y = np.arange(len(rows))
    fig, ax = plt.subplots(
        figsize=(12, max(5.8, len(rows) * 0.55)), constrained_layout=True
    )
    left = np.zeros(len(rows))
    for field, name in event_fields:
        values = [
            (number(row, field) or 0.0) * 1_000_000.0 / cycle
            if cycle > 0 else 0.0
            for row, cycle in zip(rows, cycles)
        ]
        ax.barh(y, values, left=left, label=name)
        left += np.array(values)
    ax.set_title(f"DWT event density per million cycles - {run_id}")
    ax.set_xlabel("Modulo event-counter deltas per million DWT cycles")
    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=8)
    ax.grid(axis="x", color="#e5e7eb", linewidth=0.8)
    ax.legend(loc="lower right", fontsize=8)
    add_source_note(fig, ["pqm4 cycle-count benchmarking; event counters are modulo, so treat density as diagnostic only"])
    save(fig, output)


def write_reference_file(out_dir: Path) -> None:
    lines = ["# Literature References", ""]
    for reference in REFERENCES:
        lines.extend([
            f"- {reference['short']}: {reference['title']}",
            f"  URL: {reference['url']}",
            f"  Used for: {reference['used_for']}",
            "",
        ])
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "kem_literature_references.md").write_text("\n".join(lines))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "run",
        help="KEM benchmark run id or path containing summary.csv.",
    )
    parser.add_argument(
        "--out-dir", type=Path,
        help="Output directory. Defaults to graphic/out/<run_id>.",
    )
    parser.add_argument("--format", default="png", choices=("png", "pdf", "svg"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    run_dir = resolve_run_dir(args.run)
    run_id = run_dir.name
    out_dir = args.out_dir or ROOT / "graphic" / "out" / run_id
    rows = load_rows(run_dir)
    ext = args.format
    plot_operation_costs(
        rows, out_dir / f"kem_literature_operation_costs.{ext}", run_id
    )
    plot_resource_tradeoff(
        rows, out_dir / f"kem_literature_resource_tradeoff.{ext}", run_id
    )
    plot_normalized_overhead(
        rows, out_dir / f"kem_literature_normalized_overhead.{ext}", run_id
    )
    plot_efficiency(rows, out_dir / f"kem_literature_efficiency.{ext}", run_id)
    plot_memory_budget(rows, out_dir / f"kem_literature_memory_budget.{ext}", run_id)
    plot_dwt_density(rows, out_dir / f"kem_literature_dwt_density.{ext}", run_id)
    write_reference_file(out_dir)
    print(out_dir / "kem_literature_references.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
