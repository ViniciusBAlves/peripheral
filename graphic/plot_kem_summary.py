#!/usr/bin/env python3
"""Plot nRF52840 key-exchange operation benchmark summaries."""

from __future__ import annotations

import argparse
import csv
import math
import sys
from pathlib import Path

try:
    import matplotlib.pyplot as plt
    import numpy as np
    from matplotlib.ticker import LogLocator, NullFormatter
except ImportError as exc:  # pragma: no cover - depends on local environment
    raise SystemExit(
        "Missing Python plotting dependency. Install matplotlib and numpy with:\n"
        "  python -m pip install matplotlib numpy"
    ) from exc


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "benchmarking" / "results"
sys.path.insert(0, str(ROOT / "benchmarking"))

from benchmarklib.algorithms import KEMS_BY_NAME  # noqa: E402


FAMILY_COLORS = {
    "classic": "#475569",
    "pqc": "#0f766e",
    "hybrid": "#7c3aed",
}

OPERATION_COLORS = {
    "Keygen": "#2563eb",
    "Encapsulation": "#0f766e",
    "Decapsulation": "#dc2626",
}

DEVICE_SUMMARY_OPERATION_COLORS = {
    "KeyGen": "#2563eb",
    "Encaps": "#dc2626",
    "Decaps": "#0891b2",
}

DEVICE_SUMMARY_FAMILY_COLORS = {
    "classic": "#64748b",
    "pqc": "#0f766e",
    "hybrid": "#c05600",
}

DWT_FIELDS = (
    ("mean_dwt_cyccnt", "Cycles", "#2563eb", False),
    ("mean_dwt_cpicnt", "CPI events", "#f97316", True),
    ("mean_dwt_lsucnt", "LSU events", "#7c3aed", True),
    ("mean_dwt_exccnt", "Exception events", "#dc2626", True),
    ("mean_dwt_sleepcnt", "Sleep events", "#64748b", True),
    ("mean_dwt_foldcnt", "Fold events", "#0f766e", True),
)


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
    if not math.isfinite(result):
        return None
    return result


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


def label(row: dict[str, str]) -> str:
    return f"{security_level(row)} {row.get('kex_group', '')}"


def sort_key(row: dict[str, str]) -> tuple[int, int, int, str]:
    name = row.get("kex_group", "")
    family_rank = 0 if name.startswith("ECDHE") else 1 if name.startswith("MLKEM") else 2
    kem = KEMS_BY_NAME.get(name)
    level = kem.nist_level if kem is not None else int(number(row, "kex_nist_level") or 99)
    order = list(KEMS_BY_NAME).index(name) if name in KEMS_BY_NAME else 99
    return family_rank, level, order, name


def family_colors(rows: list[dict[str, str]]) -> list[str]:
    return [FAMILY_COLORS.get(kem_family(row), "#64748b") for row in rows]


def add_family_legend(ax, rows: list[dict[str, str]]) -> None:
    present = {kem_family(row) for row in rows}
    handles = [
        plt.Line2D([0], [0], marker="s", color="w", markerfacecolor=color,
                   markersize=9, label=name.title())
        for name, color in FAMILY_COLORS.items()
        if name in present
    ]
    ax.legend(handles=handles, loc="upper right", frameon=True, fontsize=8)


def add_device_family_legend(ax, rows: list[dict[str, str]]) -> None:
    present = {kem_family(row) for row in rows}
    handles = [
        plt.Line2D([0], [0], marker="s", color="w", markerfacecolor=color,
                   markersize=9, label=name.title())
        for name, color in DEVICE_SUMMARY_FAMILY_COLORS.items()
        if name in present
    ]
    ax.legend(handles=handles, loc="lower right", frameon=True, fontsize=8)


def save(fig, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    print(output)


def pad_axis(ax, values: list[float], log_scale: bool = False) -> None:
    positive = [value for value in values if value > 0]
    if not positive:
        return
    if log_scale:
        ax.set_xscale("log")
        ax.set_xlim(left=max(min(positive) * 0.65, 0.001), right=max(positive) * 1.8)
    else:
        ax.set_xlim(right=max(positive) * 1.18)


def clean_log_axis(ax) -> None:
    ax.xaxis.set_major_locator(LogLocator(base=10.0))
    ax.xaxis.set_minor_locator(LogLocator(base=10.0, subs=np.arange(2, 10) * 0.1))
    ax.xaxis.set_minor_formatter(NullFormatter())


def annotate_bars(ax, bars, values: list[float], suffix: str = "") -> None:
    for bar, value in zip(bars, values):
        if value <= 0:
            continue
        ax.text(
            bar.get_width(), bar.get_y() + bar.get_height() / 2,
            f" {value:.2f}{suffix}", va="center", ha="left", fontsize=8,
        )


def plot_device_summary(rows: list[dict[str, str]], output: Path, run_id: str) -> None:
    rows = sorted(rows, key=lambda row: number(row, "mean_kem_total_ms") or float("inf"))
    y = np.arange(len(rows))
    names = [row.get("kex_group", "") for row in rows]
    height = 0.22
    fig, axes = plt.subplots(
        1, 3, figsize=(16, max(5.0, len(rows) * 0.46)),
        sharey=True, constrained_layout=True,
    )

    time_fields = (
        ("mean_kem_keygen_ms", "KeyGen", -height),
        ("mean_kem_encapsulation_ms", "Encaps", 0.0),
        ("mean_kem_decapsulation_ms", "Decaps", height),
    )
    time_values: list[float] = []
    for field, label_name, offset in time_fields:
        values = [(number(row, field) or 0.0) / 1000.0 for row in rows]
        time_values.extend(values)
        axes[0].barh(
            y + offset, values, height=height,
            color=DEVICE_SUMMARY_OPERATION_COLORS[label_name],
            edgecolor="#111827", linewidth=0.25, label=label_name,
        )
    totals_s = [(number(row, "mean_kem_total_ms") or 0.0) / 1000.0 for row in rows]
    time_values.extend(totals_s)
    axes[0].scatter(
        totals_s, y, marker="|", s=170, linewidths=1.6,
        color="#111827", label="Total", zorder=3,
    )
    for ypos, total_s in zip(y, totals_s):
        if total_s > 0:
            axes[0].text(total_s * 1.07, ypos, f"{total_s:.3f} s",
                         va="center", ha="left", fontsize=7)
    axes[0].set_xlabel("Mean time (seconds)")
    axes[0].set_xscale("log")
    axes[0].set_yticks(y)
    axes[0].set_yticklabels(names, fontsize=8)
    axes[0].grid(axis="x", color="#d1d5db", linestyle=":", linewidth=0.65)
    axes[0].legend(title="Operations", loc="upper right", frameon=True, fontsize=7)
    pad_axis(axes[0], time_values, log_scale=True)
    clean_log_axis(axes[0])

    families = [kem_family(row) for row in rows]
    colors = [DEVICE_SUMMARY_FAMILY_COLORS.get(family, "#64748b") for family in families]
    memory_kb = [(number(row, "max_client_heap_peak_bytes") or 0.0) / 1024.0 for row in rows]
    bars = axes[1].barh(
        y, memory_kb, color=colors, edgecolor="#111827", linewidth=0.25
    )
    axes[1].set_xlabel("Peak memory (KB)")
    axes[1].grid(axis="x", color="#d1d5db", linestyle=":", linewidth=0.65)
    annotate_bars(axes[1], bars, memory_kb, " KB")
    pad_axis(axes[1], memory_kb)
    if memory_kb:
        axes[1].set_xlim(right=max(memory_kb) * 1.45)
    add_device_family_legend(axes[1], rows)

    output_bytes = [
        sum(
            number(row, field) or 0.0
            for field in (
                "kex_public_key_bytes",
                "kex_ciphertext_bytes",
                "kex_shared_secret_bytes",
            )
        )
        for row in rows
    ]
    bars = axes[2].barh(
        y, output_bytes, color=colors, edgecolor="#111827", linewidth=0.25
    )
    axes[2].set_xlabel("Generated output (bytes)")
    axes[2].set_xscale("log")
    axes[2].grid(axis="x", color="#d1d5db", linestyle=":", linewidth=0.65)
    for bar, value in zip(bars, output_bytes):
        if value > 0:
            axes[2].text(
                bar.get_width() * 1.05, bar.get_y() + bar.get_height() / 2,
                f"{value:,.0f} B", va="center", ha="left", fontsize=7,
    )
    pad_axis(axes[2], output_bytes, log_scale=True)
    clean_log_axis(axes[2])

    for ax in axes:
        ax.invert_yaxis()
    fig.suptitle(f"On-device KEM benchmark - {run_id}", fontsize=13)
    save(fig, output)


def plot_operation_time(rows: list[dict[str, str]], output: Path, run_id: str) -> None:
    fields = (
        ("mean_kem_keygen_ms", "Keygen"),
        ("mean_kem_encapsulation_ms", "Encapsulation"),
        ("mean_kem_decapsulation_ms", "Decapsulation"),
    )
    y = np.arange(len(rows))
    height = 0.24
    fig, ax = plt.subplots(
        figsize=(12, max(5.5, len(rows) * 0.55)), constrained_layout=True
    )
    all_values: list[float] = []
    for offset, (field, name) in zip((-height, 0.0, height), fields):
        values = [number(row, field) or 0.0 for row in rows]
        all_values.extend(values)
        bars = ax.barh(
            y + offset, values, height=height, label=name,
            color=OPERATION_COLORS[name], edgecolor="#111827", linewidth=0.3,
        )
        annotate_bars(ax, bars, values, " ms")
    ax.set_title(f"KEM operation wall time - {run_id}")
    ax.set_xlabel("Mean operation time (ms, log scale)")
    ax.set_yticks(y)
    ax.set_yticklabels([label(row) for row in rows], fontsize=8)
    ax.grid(axis="x", color="#e5e7eb", linewidth=0.8)
    ax.legend(loc="lower right")
    pad_axis(ax, all_values, log_scale=True)
    save(fig, output)


def plot_time_share(rows: list[dict[str, str]], output: Path, run_id: str) -> None:
    fields = (
        ("mean_kem_keygen_ms", "Keygen"),
        ("mean_kem_encapsulation_ms", "Encapsulation"),
        ("mean_kem_decapsulation_ms", "Decapsulation"),
    )
    y = np.arange(len(rows))
    left = np.zeros(len(rows))
    fig, ax = plt.subplots(
        figsize=(11, max(5.5, len(rows) * 0.52)), constrained_layout=True
    )
    for field, name in fields:
        values = []
        for row in rows:
            total = number(row, "mean_kem_total_ms") or 0.0
            value = number(row, field) or 0.0
            values.append((100.0 * value / total) if total > 0 else 0.0)
        ax.barh(
            y, values, left=left, label=name, color=OPERATION_COLORS[name],
            edgecolor="white", linewidth=0.4,
        )
        left += np.array(values)
    ax.set_title(f"KEM operation share of total wall time - {run_id}")
    ax.set_xlabel("Share of total KEM time (%)")
    ax.set_xlim(0, 100)
    ax.set_yticks(y)
    ax.set_yticklabels([label(row) for row in rows], fontsize=8)
    ax.legend(loc="lower right")
    ax.grid(axis="x", color="#e5e7eb", linewidth=0.8)
    save(fig, output)


def plot_total_time(rows: list[dict[str, str]], output: Path, run_id: str) -> None:
    values = [number(row, "mean_kem_total_ms") or 0.0 for row in rows]
    fig, ax = plt.subplots(
        figsize=(11, max(5.5, len(rows) * 0.52)), constrained_layout=True
    )
    bars = ax.barh(
        np.arange(len(rows)), values, color=family_colors(rows),
        edgecolor="#111827", linewidth=0.35,
    )
    ax.set_title(f"Total KEM wall time - {run_id}")
    ax.set_xlabel("Mean total time (ms, log scale)")
    ax.set_yticks(np.arange(len(rows)))
    ax.set_yticklabels([label(row) for row in rows], fontsize=8)
    ax.grid(axis="x", color="#e5e7eb", linewidth=0.8)
    pad_axis(ax, values, log_scale=True)
    annotate_bars(ax, bars, values, " ms")
    add_family_legend(ax, rows)
    save(fig, output)


def plot_cpu_wall(rows: list[dict[str, str]], output: Path, run_id: str) -> None:
    labels = [label(row) for row in rows]
    wall = [number(row, "mean_kem_total_ms") or 0.0 for row in rows]
    cpu = [number(row, "mean_cpu_ms") or 0.0 for row in rows]
    ratio = [
        min((cpu_value / wall_value) * 100.0, 100.0) if wall_value > 0 else 0.0
        for cpu_value, wall_value in zip(cpu, wall)
    ]
    y = np.arange(len(rows))
    fig, axes = plt.subplots(
        1, 2, figsize=(14, max(5.5, len(rows) * 0.52)),
        constrained_layout=True,
    )
    axes[0].barh(y - 0.17, wall, height=0.34, label="Wall", color="#2563eb")
    axes[0].barh(y + 0.17, cpu, height=0.34, label="CPU", color="#f97316")
    axes[0].set_title("Wall vs CPU time")
    axes[0].set_xlabel("Mean time (ms, log scale)")
    axes[0].set_yticks(y)
    axes[0].set_yticklabels(labels, fontsize=8)
    axes[0].grid(axis="x", color="#e5e7eb", linewidth=0.8)
    axes[0].legend(loc="lower right")
    pad_axis(axes[0], wall + cpu, log_scale=True)
    bars = axes[1].barh(
        y, ratio, color=family_colors(rows), edgecolor="#111827", linewidth=0.35
    )
    axes[1].set_title("CPU occupancy during measured operation")
    axes[1].set_xlabel("CPU time / wall time (%)")
    axes[1].set_xlim(0, 100)
    axes[1].set_yticks(y)
    axes[1].set_yticklabels([])
    axes[1].grid(axis="x", color="#e5e7eb", linewidth=0.8)
    annotate_bars(axes[1], bars, ratio, "%")
    fig.suptitle(f"KEM CPU vs wall time - {run_id}", fontsize=14)
    save(fig, output)


def plot_resource_pressure(
    rows: list[dict[str, str]], output: Path, run_id: str
) -> None:
    labels = [label(row) for row in rows]
    heap_kb = [(number(row, "max_client_heap_peak_bytes") or 0.0) / 1024.0 for row in rows]
    heap_pct = [number(row, "max_client_heap_peak_usage_percent") or 0.0 for row in rows]
    ram_kb = [(number(row, "firmware_static_ram_used_bytes") or 0.0) / 1024.0 for row in rows]
    ram_pct = [number(row, "firmware_static_ram_usage_percent") or 0.0 for row in rows]
    y = np.arange(len(rows))
    fig, axes = plt.subplots(
        1, 2, figsize=(14, max(5.5, len(rows) * 0.52)),
        constrained_layout=True,
    )
    bars = axes[0].barh(
        y, heap_kb, color=family_colors(rows), edgecolor="#111827", linewidth=0.35
    )
    axes[0].set_title("Benchmark heap peak")
    axes[0].set_xlabel("Peak heap allocated (KiB)")
    axes[0].set_yticks(y)
    axes[0].set_yticklabels(labels, fontsize=8)
    axes[0].grid(axis="x", color="#e5e7eb", linewidth=0.8)
    annotate_bars(axes[0], bars, heap_pct, "%")
    pad_axis(axes[0], heap_kb)

    bars = axes[1].barh(
        y, ram_kb, color=family_colors(rows), edgecolor="#111827", linewidth=0.35
    )
    axes[1].set_title("Firmware static RAM")
    axes[1].set_xlabel("Static RAM image size (KiB)")
    axes[1].set_yticks(y)
    axes[1].set_yticklabels([])
    axes[1].grid(axis="x", color="#e5e7eb", linewidth=0.8)
    annotate_bars(axes[1], bars, ram_pct, "%")
    pad_axis(axes[1], ram_kb)
    fig.suptitle(f"KEM resource pressure - {run_id}", fontsize=14)
    save(fig, output)


def plot_size_vs_time(rows: list[dict[str, str]], output: Path, run_id: str) -> None:
    fig, ax = plt.subplots(figsize=(10.5, 7), constrained_layout=True)
    for row in rows:
        bytes_out = sum(
            number(row, field) or 0.0
            for field in (
                "kex_public_key_bytes",
                "kex_ciphertext_bytes",
                "kex_shared_secret_bytes",
            )
        )
        total = number(row, "mean_kem_total_ms") or 0.0
        heap = (number(row, "max_client_heap_peak_bytes") or 0.0) / 1024.0
        ax.scatter(
            bytes_out, total, s=max(55, heap * 1.5),
            color=FAMILY_COLORS.get(kem_family(row), "#64748b"),
            edgecolor="#111827", linewidth=0.5, alpha=0.86,
        )
        ax.annotate(
            label(row), (bytes_out, total), xytext=(5, 4),
            textcoords="offset points", fontsize=8,
        )
    ax.set_title(f"KEM size vs time - {run_id}")
    ax.set_xlabel("Public key + ciphertext + shared secret bytes")
    ax.set_ylabel("Mean total time (ms, log scale)")
    ax.set_yscale("log")
    ax.grid(True, color="#e5e7eb", linewidth=0.8)
    add_family_legend(ax, rows)
    save(fig, output)


def plot_dwt_counters(rows: list[dict[str, str]], output: Path, run_id: str) -> None:
    present = [
        item for item in DWT_FIELDS
        if any((number(row, item[0]) or 0.0) > 0.0 for row in rows)
    ]
    if not present:
        print("warning: no DWT counter values found")
        return
    y = np.arange(len(rows))
    fig, axes = plt.subplots(
        len(present), 1, figsize=(12, max(6, len(rows) * 0.42 * len(present))),
        constrained_layout=True, squeeze=False,
    )
    for ax, (field, title, color, modulo) in zip(axes[:, 0], present):
        values = [number(row, field) or 0.0 for row in rows]
        bars = ax.barh(
            y, values, color=color, edgecolor="#111827", linewidth=0.25
        )
        suffix = " modulo mean" if modulo else ""
        ax.set_title(f"{title}{suffix}")
        ax.set_xlabel("Mean counter delta")
        ax.set_yticks(y)
        ax.set_yticklabels([label(row) for row in rows], fontsize=8)
        ax.grid(axis="x", color="#e5e7eb", linewidth=0.8)
        pad_axis(ax, values, log_scale=True)
        if len(rows) <= 10:
            annotate_bars(ax, bars, values)
    fig.suptitle(f"KEM DWT counter deltas - {run_id}", fontsize=14)
    save(fig, output)


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
    extension = args.format
    plot_device_summary(rows, out_dir / f"kem_device_summary.{extension}", run_id)
    plot_total_time(rows, out_dir / f"kem_total_time.{extension}", run_id)
    plot_operation_time(rows, out_dir / f"kem_operation_time.{extension}", run_id)
    plot_time_share(rows, out_dir / f"kem_operation_share.{extension}", run_id)
    plot_cpu_wall(rows, out_dir / f"kem_cpu_wall.{extension}", run_id)
    plot_resource_pressure(rows, out_dir / f"kem_resource_pressure.{extension}", run_id)
    plot_size_vs_time(rows, out_dir / f"kem_size_vs_time.{extension}", run_id)
    plot_dwt_counters(rows, out_dir / f"kem_dwt_counters.{extension}", run_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
