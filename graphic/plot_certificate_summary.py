#!/usr/bin/env python3
"""Plot certificate benchmark summary metrics from a result directory."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

try:
    import matplotlib.pyplot as plt
    import numpy as np
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Missing Python plotting dependency. Install matplotlib and numpy with:\n"
        "  python -m pip install matplotlib numpy"
    ) from exc


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS_ROOT = PROJECT_ROOT / "benchmarking" / "results"
DEFAULT_OUT_ROOT = PROJECT_ROOT / "graphic" / "out"


def resolve_run_dir(value: str) -> Path:
    path = Path(value).expanduser()
    if path.exists():
        return path.resolve()

    candidate = DEFAULT_RESULTS_ROOT / value
    if candidate.exists():
        return candidate.resolve()

    raise FileNotFoundError(
        f"Certificate benchmark result directory not found: {value}. "
        f"Tried {path} and {candidate}."
    )


def float_or_none(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def load_summary(run_dir: Path, include_failed: bool) -> list[dict[str, str]]:
    summary_csv = run_dir / "summary.csv"
    if not summary_csv.exists():
        raise FileNotFoundError(f"summary.csv not found in {run_dir}")

    with summary_csv.open(newline="") as fp:
        rows = list(csv.DictReader(fp))

    usable = []
    for row in rows:
        if not include_failed and row.get("status") != "success":
            continue
        if float_or_none(row.get("mean_wall_ms")) is None:
            continue
        usable.append(row)
    if not usable:
        raise ValueError(f"no plottable rows found in {summary_csv}")
    return usable


def row_label(row: dict[str, str]) -> str:
    component = row.get("component", "")
    signature = row.get("cert_sig_alg", "")
    if component == "client_identity":
        return "Client key + CSR"
    if component == "client_certificate":
        return f"Client cert: {signature} (board)"
    return signature


def row_color(row: dict[str, str]) -> str:
    component = row.get("component", "")
    builder = row.get("builder", "")
    if component in {"client_identity", "client_certificate"}:
        return "#2563eb"
    if builder == "wolfssl-hbs":
        return "#7c3aed"
    if row.get("sig_family") == "pqc":
        return "#0f766e"
    return "#64748b"


def numeric(rows: list[dict[str, str]], field: str) -> list[float]:
    values = []
    for row in rows:
        value = float_or_none(row.get(field))
        values.append(value if value is not None else 0.0)
    return values


def positive_rows(rows: list[dict[str, str]], fields: list[str]) -> list[dict[str, str]]:
    return [
        row for row in rows
        if any((float_or_none(row.get(field)) or 0.0) > 0 for field in fields)
    ]


def cpu_ms(row: dict[str, str]) -> float:
    return (
        float_or_none(row.get("mean_cpu_ms"))
        or float_or_none(row.get("mean_client_cpu_ms"))
        or 0.0
    )


def memory_kb(row: dict[str, str]) -> float:
    rss = float_or_none(row.get("max_rss_kb"))
    if rss is not None:
        return rss
    heap_bytes = float_or_none(row.get("max_client_heap_peak_bytes"))
    return heap_bytes / 1024.0 if heap_bytes is not None else 0.0


def output_size_bytes(row: dict[str, str]) -> float:
    total = float_or_none(row.get("mean_output_total_bytes"))
    if total is not None:
        return total
    cert = float_or_none(row.get("client_cert_der_bytes")) or 0.0
    key = float_or_none(row.get("client_key_der_bytes")) or 0.0
    return cert + key


PHASE_FIELDS = [
    ("mean_keygen_cpu_ms", "Keygen", "#2563eb"),
    ("mean_make_cert_cpu_ms", "Make cert", "#64748b"),
    ("mean_sign_cert_cpu_ms", "Sign cert", "#dc2626"),
    ("mean_parse_cert_cpu_ms", "Parse verify", "#0f766e"),
    ("mean_key_export_cpu_ms", "Key export", "#9333ea"),
]

THREAD_CPU_FIELDS = [
    ("mean_thread_main_cpu_percent", "main", "#2563eb"),
    ("mean_thread_sysworkq_cpu_percent", "sysworkq", "#64748b"),
    ("mean_thread_bt_rx_cpu_percent", "BT RX", "#f97316"),
    ("mean_thread_bt_tx_cpu_percent", "BT TX", "#eab308"),
    ("mean_thread_idle_cpu_percent", "idle", "#0f766e"),
    ("mean_thread_other_cpu_percent", "other", "#9333ea"),
]


def phase_values(row: dict[str, str]) -> list[float]:
    return [float_or_none(row.get(field)) or 0.0 for field, _label, _color in PHASE_FIELDS]


def phase_total(row: dict[str, str]) -> float:
    explicit = float_or_none(row.get("mean_phase_cpu_total_ms"))
    if explicit is not None:
        return explicit
    return sum(phase_values(row))


def sort_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return sorted(
        rows,
        key=lambda row: (
            row.get("component") not in {"client_identity", "client_certificate"},
            float_or_none(row.get("mean_wall_ms")) or 0.0,
            row_label(row).lower(),
        ),
    )


def annotate_bars(ax, bars, values: list[float], *, suffix: str = "") -> None:
    for bar, value in zip(bars, values):
        if value <= 0:
            continue
        ax.annotate(
            f"{value:,.0f}{suffix}",
            xy=(value, bar.get_y() + bar.get_height() / 2),
            xytext=(4, 0),
            textcoords="offset points",
            ha="left",
            va="center",
            fontsize=8,
        )


def pad_x_axis(ax, values: list[float], *, log_scale: bool) -> None:
    positive = [value for value in values if value > 0]
    if not positive:
        return
    if log_scale:
        ax.set_xlim(min(positive) / 1.4, max(positive) * 2.4)
    else:
        ax.set_xlim(0, max(positive) * 1.28)


def plot_summary(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
    *,
    log_time: bool,
) -> None:
    rows = sort_rows(rows)
    labels = [row_label(row) for row in rows]
    colors = [row_color(row) for row in rows]
    positions = np.arange(len(rows))

    wall_ms = numeric(rows, "mean_wall_ms")
    cpu_values_ms = [cpu_ms(row) for row in rows]
    memory_values_kb = [memory_kb(row) for row in rows]
    output_bytes = [output_size_bytes(row) for row in rows]

    height = max(8.0, len(rows) * 0.42)
    fig, axes = plt.subplots(
        1, 3,
        figsize=(18, height),
        sharey=True,
        constrained_layout=True,
    )
    fig.suptitle(f"Certificate benchmark summary - {run_id}", fontsize=15)

    wall_bars = axes[0].barh(
        positions, wall_ms, color=colors, edgecolor="#111827", linewidth=0.35
    )
    axes[0].barh(
        positions, cpu_values_ms, color="none", edgecolor="#f97316",
        linewidth=1.2, hatch="//"
    )
    axes[0].set_xlabel("Mean time (ms)")
    axes[0].set_yticks(positions)
    axes[0].set_yticklabels(labels, fontsize=9)
    axes[0].grid(axis="x", linestyle=":", alpha=0.35)
    if log_time:
        axes[0].set_xscale("log")
    pad_x_axis(axes[0], wall_ms, log_scale=log_time)
    annotate_bars(axes[0], wall_bars, wall_ms, suffix=" ms")

    memory_bars = axes[1].barh(
        positions, memory_values_kb, color=colors, edgecolor="#111827", linewidth=0.35
    )
    axes[1].set_xlabel("Peak memory (KB)")
    axes[1].grid(axis="x", linestyle=":", alpha=0.35)
    pad_x_axis(axes[1], memory_values_kb, log_scale=False)
    annotate_bars(axes[1], memory_bars, memory_values_kb, suffix=" KB")

    size_bars = axes[2].barh(
        positions, output_bytes, color=colors, edgecolor="#111827",
        linewidth=0.35
    )
    axes[2].set_xlabel("Generated output (bytes)")
    axes[2].grid(axis="x", linestyle=":", alpha=0.35)
    axes[2].set_xscale("log")
    pad_x_axis(axes[2], output_bytes, log_scale=True)
    annotate_bars(axes[2], size_bars, output_bytes, suffix=" B")

    for ax in axes:
        ax.invert_yaxis()

    legend_handles = [
        plt.Rectangle((0, 0), 1, 1, color="#2563eb", label="Client/wolfSSL"),
        plt.Rectangle((0, 0), 1, 1, color="#64748b", label="Classic/OpenSSL"),
        plt.Rectangle((0, 0), 1, 1, color="#0f766e", label="PQC/OpenSSL"),
        plt.Rectangle((0, 0), 1, 1, color="#7c3aed", label="HBS/wolfSSL"),
        plt.Rectangle(
            (0, 0), 1, 1, facecolor="none", edgecolor="#f97316",
            hatch="//", label="CPU time overlay"
        ),
    ]
    axes[0].legend(handles=legend_handles, loc="upper right", fontsize=8)

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)


def plot_phase_breakdown(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    rows = sort_rows(positive_rows(rows, [field for field, _label, _color in PHASE_FIELDS]))
    if not rows:
        return False

    labels = [row_label(row) for row in rows]
    positions = np.arange(len(rows))
    height = max(7.0, len(rows) * 0.46)
    fig, ax = plt.subplots(figsize=(12, height), constrained_layout=True)
    fig.suptitle(f"Certificate CPU phase breakdown - {run_id}", fontsize=15)

    left = np.zeros(len(rows))
    for field, label, color in PHASE_FIELDS:
        values = np.array(numeric(rows, field))
        ax.barh(
            positions, values, left=left, label=label, color=color,
            edgecolor="#111827", linewidth=0.25
        )
        left += values

    totals = [phase_total(row) for row in rows]
    annotate_bars(ax, ax.barh(positions, [0] * len(rows), left=left), totals, suffix=" ms")
    ax.set_xlabel("Mean phase CPU time (ms)")
    ax.set_yticks(positions)
    ax.set_yticklabels(labels, fontsize=9)
    ax.grid(axis="x", linestyle=":", alpha=0.35)
    ax.legend(loc="lower right", fontsize=8)
    ax.invert_yaxis()
    pad_x_axis(ax, totals, log_scale=False)

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return True


def plot_phase_share(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    rows = sort_rows([
        row for row in rows
        if phase_total(row) > 0
    ])
    if not rows:
        return False

    labels = [row_label(row) for row in rows]
    positions = np.arange(len(rows))
    height = max(7.0, len(rows) * 0.46)
    fig, ax = plt.subplots(figsize=(12, height), constrained_layout=True)
    fig.suptitle(f"Certificate CPU phase share - {run_id}", fontsize=15)

    left = np.zeros(len(rows))
    totals = np.array([phase_total(row) for row in rows])
    for field, label, color in PHASE_FIELDS:
        values = np.array(numeric(rows, field))
        shares = np.divide(
            values * 100.0,
            totals,
            out=np.zeros_like(values),
            where=totals > 0,
        )
        ax.barh(
            positions, shares, left=left, label=label, color=color,
            edgecolor="#111827", linewidth=0.25
        )
        left += shares

    ax.set_xlabel("Share of measured phase CPU time (%)")
    ax.set_xlim(0, 100)
    ax.set_yticks(positions)
    ax.set_yticklabels(labels, fontsize=9)
    ax.grid(axis="x", linestyle=":", alpha=0.35)
    ax.legend(loc="lower right", fontsize=8)
    ax.invert_yaxis()

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return True


def plot_cpu_efficiency(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    rows = sort_rows([
        row for row in rows
        if cpu_ms(row) > 0 and output_size_bytes(row) > 0
    ])
    if not rows:
        return False

    labels = [row_label(row) for row in rows]
    colors = [row_color(row) for row in rows]
    positions = np.arange(len(rows))
    output_kb = [output_size_bytes(row) / 1024.0 for row in rows]
    cpu_per_kb = [
        cpu_ms(row) / kb if kb > 0 else 0.0
        for row, kb in zip(rows, output_kb)
    ]
    height = max(8.0, len(rows) * 0.42)
    fig, axes = plt.subplots(
        1, 2,
        figsize=(16, height),
        constrained_layout=True,
    )
    fig.suptitle(f"Certificate CPU cost normalized by output - {run_id}", fontsize=15)

    bars = axes[0].barh(
        positions, cpu_per_kb, color=colors, edgecolor="#111827", linewidth=0.35
    )
    axes[0].set_xlabel("CPU ms per output KB")
    axes[0].set_yticks(positions)
    axes[0].set_yticklabels(labels, fontsize=9)
    axes[0].grid(axis="x", linestyle=":", alpha=0.35)
    axes[0].set_xscale("log")
    pad_x_axis(axes[0], cpu_per_kb, log_scale=True)
    annotate_bars(axes[0], bars, cpu_per_kb)

    scatter_sizes = [
        max(30.0, min(260.0, memory_kb(row) / 2.0))
        for row in rows
    ]
    axes[1].scatter(
        output_kb,
        [cpu_ms(row) for row in rows],
        s=scatter_sizes,
        c=colors,
        edgecolors="#111827",
        linewidths=0.35,
        alpha=0.88,
    )
    for x, y, label in zip(output_kb, [cpu_ms(row) for row in rows], labels):
        axes[1].annotate(label, (x, y), xytext=(4, 2), textcoords="offset points", fontsize=7)
    axes[1].set_xlabel("Generated output (KB)")
    axes[1].set_ylabel("CPU time (ms)")
    axes[1].set_xscale("log")
    axes[1].set_yscale("log")
    axes[1].grid(linestyle=":", alpha=0.35)

    axes[0].text(
        0.02, 0.02,
        "Right plot bubble size follows peak memory where available.",
        transform=axes[0].transAxes,
        fontsize=8,
        color="#374151",
    )
    axes[0].invert_yaxis()

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return True


def plot_resource_pressure(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    fields = ["max_client_heap_peak_bytes", "max_thread_stack_peak_percent"]
    rows = sort_rows(positive_rows(rows, fields))
    if not rows:
        return False

    labels = [row_label(row) for row in rows]
    positions = np.arange(len(rows))
    heap_kb = [
        (float_or_none(row.get("max_client_heap_peak_bytes")) or 0.0) / 1024.0
        for row in rows
    ]
    stack_pct = numeric(rows, "max_thread_stack_peak_percent")
    phase_verify = [row.get("phase_cpu_verify", "") for row in rows]

    height = max(7.0, len(rows) * 0.46)
    fig, axes = plt.subplots(
        1, 2,
        figsize=(15, height),
        sharey=True,
        constrained_layout=True,
    )
    fig.suptitle(f"Board certificate resource pressure - {run_id}", fontsize=15)

    heap_bars = axes[0].barh(
        positions, heap_kb, color="#2563eb", edgecolor="#111827", linewidth=0.35
    )
    axes[0].set_xlabel("Peak wolfSSL heap (KB)")
    axes[0].set_yticks(positions)
    axes[0].set_yticklabels(labels, fontsize=9)
    axes[0].grid(axis="x", linestyle=":", alpha=0.35)
    pad_x_axis(axes[0], heap_kb, log_scale=False)
    annotate_bars(axes[0], heap_bars, heap_kb, suffix=" KB")

    stack_colors = [
        "#dc2626" if verify == "fail" else "#0f766e"
        for verify in phase_verify
    ]
    stack_bars = axes[1].barh(
        positions, stack_pct, color=stack_colors, edgecolor="#111827", linewidth=0.35
    )
    axes[1].set_xlabel("Peak thread stack usage (%)")
    axes[1].set_xlim(0, max(100.0, max(stack_pct) * 1.12 if stack_pct else 100.0))
    axes[1].grid(axis="x", linestyle=":", alpha=0.35)
    annotate_bars(axes[1], stack_bars, stack_pct, suffix="%")

    for ax in axes:
        ax.invert_yaxis()

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return True


def plot_thread_cpu_breakdown(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    fields = [field for field, _label, _color in THREAD_CPU_FIELDS]
    rows = sort_rows(positive_rows(rows, fields))
    if not rows:
        return False

    labels = [row_label(row) for row in rows]
    positions = np.arange(len(rows))
    height = max(7.0, len(rows) * 0.46)
    fig, ax = plt.subplots(figsize=(12, height), constrained_layout=True)
    fig.suptitle(f"Board certgen per-thread CPU share - {run_id}", fontsize=15)

    left = np.zeros(len(rows))
    for field, label, color in THREAD_CPU_FIELDS:
        values = np.array(numeric(rows, field))
        ax.barh(
            positions, values, left=left, label=label, color=color,
            edgecolor="#111827", linewidth=0.25
        )
        left += values

    ax.set_xlabel("Share of elapsed CPU window (%)")
    ax.set_xlim(0, max(100.0, max(left) * 1.08 if len(left) else 100.0))
    ax.set_yticks(positions)
    ax.set_yticklabels(labels, fontsize=9)
    ax.grid(axis="x", linestyle=":", alpha=0.35)
    ax.legend(loc="lower right", fontsize=8)
    ax.invert_yaxis()

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "run",
        help="Certificate benchmark run id or path containing summary.csv.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        help="Directory for graph output. Defaults to graphic/out/<run_id>.",
    )
    parser.add_argument(
        "--format",
        choices=("png", "pdf", "svg"),
        default="png",
        help="Output image format.",
    )
    parser.add_argument(
        "--linear-time",
        action="store_true",
        help="Use a linear time axis instead of the default log scale.",
    )
    parser.add_argument(
        "--include-failed",
        action="store_true",
        help="Include failed rows that still have timing data.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_dir = resolve_run_dir(args.run)
    rows = load_summary(run_dir, include_failed=args.include_failed)
    out_dir = args.out_dir or DEFAULT_OUT_ROOT / run_dir.name
    extension = args.format
    outputs: list[Path] = []

    output = out_dir / f"certificate_summary.{extension}"
    plot_summary(rows, output, run_dir.name, log_time=not args.linear_time)
    outputs.append(output)

    optional_plots = [
        (
            plot_phase_breakdown,
            out_dir / f"certificate_cpu_phase_breakdown.{extension}",
        ),
        (
            plot_phase_share,
            out_dir / f"certificate_cpu_phase_share.{extension}",
        ),
        (
            plot_cpu_efficiency,
            out_dir / f"certificate_cpu_efficiency.{extension}",
        ),
        (
            plot_resource_pressure,
            out_dir / f"certificate_resource_pressure.{extension}",
        ),
        (
            plot_thread_cpu_breakdown,
            out_dir / f"certificate_thread_cpu_breakdown.{extension}",
        ),
    ]
    for plotter, path in optional_plots:
        if plotter(rows, path, run_dir.name):
            outputs.append(path)

    print(f"rows={len(rows)}")
    print(f"format={extension}")
    for path in outputs:
        print(f"output={path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
