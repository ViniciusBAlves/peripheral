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
    return signature


def row_color(row: dict[str, str]) -> str:
    component = row.get("component", "")
    builder = row.get("builder", "")
    if component == "client_identity":
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


def sort_rows(rows: list[dict[str, str]]) -> list[dict[str, str]]:
    return sorted(
        rows,
        key=lambda row: (
            row.get("component") != "client_identity",
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
    cpu_ms = numeric(rows, "mean_cpu_ms")
    rss_kb = numeric(rows, "max_rss_kb")
    output_bytes = numeric(rows, "mean_output_total_bytes")

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
        positions, cpu_ms, color="none", edgecolor="#f97316",
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

    rss_bars = axes[1].barh(
        positions, rss_kb, color=colors, edgecolor="#111827", linewidth=0.35
    )
    axes[1].set_xlabel("Peak RSS (KB)")
    axes[1].grid(axis="x", linestyle=":", alpha=0.35)
    pad_x_axis(axes[1], rss_kb, log_scale=False)
    annotate_bars(axes[1], rss_bars, rss_kb, suffix=" KB")

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
    axes[0].legend(handles=legend_handles, loc="lower right", fontsize=8)

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)


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
    output = out_dir / f"certificate_summary.{extension}"

    plot_summary(rows, output, run_dir.name, log_time=not args.linear_time)

    print(f"rows={len(rows)}")
    print(f"format={extension}")
    print(f"output={output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
