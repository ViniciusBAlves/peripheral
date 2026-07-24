#!/usr/bin/env python3
"""Plot and tabulate on-device certificate or KEM benchmark results."""

from __future__ import annotations

import argparse
import csv
import math
import re
import statistics
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Sequence

try:
    import matplotlib.pyplot as plt
    import numpy as np
    from matplotlib.ticker import NullFormatter
except ModuleNotFoundError as exc:  # pragma: no cover - CLI dependency guard
    raise SystemExit(
        "Missing Python plotting dependencies. Install them with:\n"
        "  python3 -m pip install -r benchmarking/requirements.txt"
    ) from exc


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS_ROOT = PROJECT_ROOT / "benchmarking" / "results"
OUTPUT_ROOT = PROJECT_ROOT / "graphic" / "out"

CERTIFICATE_OPERATIONS = (
    ("keygen_seconds", "KeyGen (s)"),
    ("make_body_seconds", "Make body (s)"),
    ("sign_seconds", "Sign (s)"),
    ("verify_seconds", "Verify (s)"),
)
KEM_OPERATIONS = (
    ("keygen_seconds", "KeyGen (s)"),
    ("encapsulation_seconds", "Encaps (s)"),
    ("decapsulation_seconds", "Decaps (s)"),
)
OPERATION_COLORS = {
    "keygen_seconds": "#2563eb",
    "make_body_seconds": "#7c3aed",
    "sign_seconds": "#f59e0b",
    "verify_seconds": "#10b981",
    "encapsulation_seconds": "#dc2626",
    "decapsulation_seconds": "#0891b2",
    "other_seconds": "#94a3b8",
}


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "run",
        help=(
            "Result directory or run ID beginning with cert_device or "
            "kem_device."
        ),
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        help="Output directory. Defaults to graphic/out/<run_id>.",
    )
    parser.add_argument(
        "--format",
        choices=("pdf", "png", "svg"),
        default="pdf",
        help="Graph format. Default: PDF.",
    )
    parser.add_argument(
        "--linear-time",
        action="store_true",
        help="Use a linear time axis instead of the default logarithmic axis.",
    )
    return parser.parse_args(argv)


def resolve_run_dir(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if path.is_dir():
        return path.resolve()
    candidate = RESULTS_ROOT / path
    if candidate.is_dir():
        return candidate.resolve()
    raise FileNotFoundError(f"Benchmark result directory not found: {value}")


def detect_benchmark_type(run_dir: Path) -> str:
    if run_dir.name.startswith("cert_device"):
        return "certificate"
    if run_dir.name.startswith("kem_device"):
        return "kem"
    raise ValueError(
        f"{run_dir.name}: expected a cert_device* or kem_device* result folder"
    )


def float_or_none(value: str | None) -> float | None:
    if value in (None, ""):
        return None
    try:
        return float(value)
    except ValueError:
        return None


def mean_field(rows: Iterable[dict[str, str]], field: str) -> float | None:
    values = [
        value
        for row in rows
        if (value := float_or_none(row.get(field))) is not None
    ]
    return statistics.mean(values) if values else None


def max_field(rows: Iterable[dict[str, str]], field: str) -> float | None:
    values = [
        value
        for row in rows
        if (value := float_or_none(row.get(field))) is not None
    ]
    return max(values) if values else None


def first_field(rows: Sequence[dict[str, str]], field: str) -> str:
    for row in rows:
        value = row.get(field, "")
        if value != "":
            return value
    return ""


def read_attempts(run_dir: Path) -> list[dict[str, str]]:
    path = run_dir / "attempts.csv"
    if not path.exists():
        raise FileNotFoundError(f"attempts.csv not found in {run_dir}")
    with path.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    if not rows:
        raise ValueError(f"{path} is empty")
    return rows


def generated_kem_bytes(row: dict[str, str]) -> float | None:
    fields = (
        "kex_public_key_bytes",
        "kex_ciphertext_bytes",
        "kex_shared_secret_bytes",
    )
    values = [float_or_none(row.get(field)) for field in fields]
    if any(value is None for value in values):
        return None
    return sum(value for value in values if value is not None)


def aggregate_certificate_rows(
    attempts: Sequence[dict[str, str]],
) -> list[dict[str, object]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in attempts:
        grouped[row.get("cert_sig_alg", "unknown")].append(row)

    output = []
    for algorithm, all_rows in grouped.items():
        success = [row for row in all_rows if row.get("status") == "success"]
        timed_out = any(row.get("status") == "timeout" for row in all_rows)
        output.append(
            {
                "algorithm": algorithm,
                "family": first_field(all_rows, "sig_family"),
                "nist_level": first_field(all_rows, "sig_nist_level"),
                "status": "success" if len(success) == len(all_rows) else
                    "mixed" if success else
                    "timeout" if timed_out else "no_success",
                "success_count": len(success),
                "attempt_count": len(all_rows),
                "mean_time_seconds": divide(
                    mean_field(success, "certificate_total_ms"), 1000.0
                ),
                "peak_memory_kb": divide(
                    max_field(success, "client_heap_peak_bytes"), 1024.0
                ),
                "generated_output_bytes": mean_field(
                    success, "certificate_der_bytes"
                ),
                "keygen_seconds": divide(
                    mean_field(success, "certificate_keygen_ms"), 1000.0
                ),
                "make_body_seconds": divide(
                    mean_field(success, "certificate_make_body_ms"), 1000.0
                ),
                "sign_seconds": divide(
                    mean_field(success, "certificate_sign_ms"), 1000.0
                ),
                "verify_seconds": divide(
                    mean_field(success, "certificate_verify_ms"), 1000.0
                ),
            }
        )
    return sort_aggregates(output)


def aggregate_kem_rows(
    attempts: Sequence[dict[str, str]],
) -> list[dict[str, object]]:
    grouped: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in attempts:
        grouped[row.get("kex_group", "unknown")].append(row)

    output = []
    for algorithm, all_rows in grouped.items():
        success = [row for row in all_rows if row.get("status") == "success"]
        generated = [
            value
            for row in success
            if (value := generated_kem_bytes(row)) is not None
        ]
        family = first_field(all_rows, "kex_family")
        if first_field(all_rows, "operation_model") == "hybrid_kem":
            family = "hybrid"
        output.append(
            {
                "algorithm": algorithm,
                "family": family,
                "nist_level": first_field(all_rows, "kex_nist_level"),
                "status": "success" if len(success) == len(all_rows) else
                    "mixed" if success else "no_success",
                "success_count": len(success),
                "attempt_count": len(all_rows),
                "mean_time_seconds": divide(
                    mean_field(success, "kem_total_ms"), 1000.0
                ),
                "peak_memory_kb": divide(
                    max_field(success, "client_heap_peak_bytes"), 1024.0
                ),
                "generated_output_bytes": (
                    statistics.mean(generated) if generated else None
                ),
                "keygen_seconds": divide(
                    mean_field(success, "kem_keygen_ms"), 1000.0
                ),
                "encapsulation_seconds": divide(
                    mean_field(success, "kem_encapsulation_ms"), 1000.0
                ),
                "decapsulation_seconds": divide(
                    mean_field(success, "kem_decapsulation_ms"), 1000.0
                ),
            }
        )
    return sort_aggregates(output)


def divide(value: float | None, divisor: float) -> float | None:
    return value / divisor if value is not None else None


def sort_aggregates(
    rows: list[dict[str, object]],
) -> list[dict[str, object]]:
    return sorted(
        rows,
        key=lambda row: (
            row["mean_time_seconds"] is None,
            float(row["mean_time_seconds"] or math.inf),
            str(row["algorithm"]).lower(),
        ),
    )


def row_color(row: dict[str, object]) -> str:
    if row.get("status") == "timeout":
        return "#b91c1c"
    family = str(row.get("family", "")).lower()
    if family == "pqc":
        return "#0f766e"
    if family == "hybrid":
        return "#b45309"
    return "#64748b"


def numeric_for_plot(
    rows: Sequence[dict[str, object]], field: str
) -> list[float]:
    return [
        float(row[field]) if row.get(field) is not None else 0.0
        for row in rows
    ]


def operation_series(
    rows: Sequence[dict[str, object]],
    benchmark_type: str,
) -> list[tuple[str, str, list[float]]]:
    operations = (
        CERTIFICATE_OPERATIONS
        if benchmark_type == "certificate"
        else KEM_OPERATIONS
    )
    series = [
        (field, label.removesuffix(" (s)"), numeric_for_plot(rows, field))
        for field, label in operations
    ]
    totals = numeric_for_plot(rows, "mean_time_seconds")
    measured_sums = [
        sum(values[index] for _, _, values in series)
        for index in range(len(rows))
    ]
    residual = [
        max(total - measured, 0.0)
        for total, measured in zip(totals, measured_sums, strict=True)
    ]
    if any(value > 1e-9 for value in residual):
        series.append(("other_seconds", "Other", residual))
    return series


def annotate_bars(
    axis: plt.Axes,
    bars,
    values: Sequence[float],
    *,
    unit: str,
    decimals: int,
) -> None:
    for bar, value in zip(bars, values, strict=True):
        if value <= 0:
            continue
        axis.annotate(
            f"{value:,.{decimals}f} {unit}",
            xy=(value, bar.get_y() + bar.get_height() / 2),
            xytext=(4, 0),
            textcoords="offset points",
            ha="left",
            va="center",
            fontsize=7,
        )


def pad_axis(
    axis: plt.Axes,
    values: Sequence[float],
    *,
    logarithmic: bool,
) -> None:
    positive = [value for value in values if value > 0]
    if not positive:
        return
    if logarithmic:
        axis.set_xlim(min(positive) / 1.5, max(positive) * 2.8)
    else:
        axis.set_xlim(0, max(positive) * 1.35)


def plot_summary(
    rows: Sequence[dict[str, object]],
    *,
    benchmark_type: str,
    run_id: str,
    output: Path,
    logarithmic_time: bool,
) -> None:
    plotted = [row for row in rows if row["mean_time_seconds"] is not None]
    if not plotted:
        raise ValueError("no successful attempts are available for plotting")

    labels = [str(row["algorithm"]) for row in plotted]
    colors = [row_color(row) for row in plotted]
    positions = np.arange(len(plotted))
    time_seconds = numeric_for_plot(plotted, "mean_time_seconds")
    memory_kb = numeric_for_plot(plotted, "peak_memory_kb")
    output_bytes = numeric_for_plot(plotted, "generated_output_bytes")
    height = max(6.0, len(plotted) * 0.44)

    figure, axes = plt.subplots(
        1,
        3,
        figsize=(19, height),
        sharey=True,
        constrained_layout=True,
    )
    title = "Certificate" if benchmark_type == "certificate" else "KEM"
    figure.suptitle(f"On-device {title} benchmark - {run_id}", fontsize=15)

    time_handles = []
    time_series = operation_series(plotted, benchmark_type)
    operation_height = 0.72 / max(len(time_series), 1)
    for index, (field, label, values) in enumerate(time_series):
        offsets = positions + (
            index - (len(time_series) - 1) / 2
        ) * operation_height
        bars = axes[0].barh(
            offsets,
            values,
            height=operation_height * 0.9,
            color=OPERATION_COLORS[field],
            edgecolor="#111827",
            linewidth=0.25,
            label=label,
        )
        time_handles.append(bars)
    measured_positions = [
        index for index, value in enumerate(time_seconds) if value > 0
    ]
    total_markers = axes[0].scatter(
        [time_seconds[index] for index in measured_positions],
        [positions[index] for index in measured_positions],
        marker="|",
        s=180,
        linewidths=2.5,
        color="#111827",
        label="Total",
        zorder=4,
    )
    axes[0].set_xlabel("Mean time (seconds)")
    axes[0].grid(axis="x", linestyle=":", alpha=0.35)
    if logarithmic_time and any(value > 0 for value in time_seconds):
        axes[0].set_xscale("log")
        axes[0].xaxis.set_minor_formatter(NullFormatter())
    time_axis_values = [
        *time_seconds,
        *(
            value
            for _, _, values in time_series
            for value in values
        ),
    ]
    pad_axis(axes[0], time_axis_values, logarithmic=logarithmic_time)
    annotate_bars(
        axes[0],
        time_handles[-1],
        time_seconds,
        unit="s",
        decimals=3,
    )
    axes[0].invert_yaxis()

    configurations = (
        (axes[1], memory_kb, "Peak memory (KB)", False, "KB", 2),
        (
            axes[2],
            output_bytes,
            "Generated output (bytes)",
            True,
            "B",
            0,
        ),
    )
    for axis, values, xlabel, logarithmic, unit, decimals in configurations:
        bars = axis.barh(
            positions,
            values,
            color=colors,
            edgecolor="#111827",
            linewidth=0.35,
        )
        axis.set_xlabel(xlabel)
        axis.grid(axis="x", linestyle=":", alpha=0.35)
        if logarithmic and any(value > 0 for value in values):
            axis.set_xscale("log")
            axis.xaxis.set_minor_formatter(NullFormatter())
        pad_axis(axis, values, logarithmic=logarithmic)
        annotate_bars(
            axis, bars, values, unit=unit, decimals=decimals
        )
        axis.invert_yaxis()

    axes[0].set_yticks(positions)
    axes[0].set_yticklabels(labels, fontsize=12)
    axes[0].legend(
        handles=[bars[0] for bars in time_handles] + [total_markers],
        labels=[bars.get_label() for bars in time_handles] + ["Total"],
        loc="upper right",
        fontsize=8,
        title="Operations",
        title_fontsize=8,
    )
    family_legend = [
        plt.Rectangle((0, 0), 1, 1, color="#64748b", label="Classic"),
        plt.Rectangle((0, 0), 1, 1, color="#0f766e", label="PQC"),
    ]
    if benchmark_type == "kem":
        family_legend.append(
            plt.Rectangle((0, 0), 1, 1, color="#b45309", label="Hybrid")
        )
    axes[1].legend(handles=family_legend, loc="lower right", fontsize=8)
    output.parent.mkdir(parents=True, exist_ok=True)
    figure.savefig(output, dpi=180)
    plt.close(figure)


def latex_escape(value: object) -> str:
    text = str(value)
    replacements = (
        ("\\", r"\textbackslash{}"),
        ("&", r"\&"),
        ("%", r"\%"),
        ("$", r"\$"),
        ("#", r"\#"),
        ("_", r"\_"),
        ("{", r"\{"),
        ("}", r"\}"),
    )
    for original, replacement in replacements:
        text = text.replace(original, replacement)
    return text


def latex_number(
    value: object,
    *,
    decimals: int,
) -> str:
    if value is None or value == "":
        return "--"
    return f"{float(value):.{decimals}f}"


def latex_label(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9:.-]+", "-", value).strip("-")


def write_latex_table(
    rows: Sequence[dict[str, object]],
    *,
    benchmark_type: str,
    run_id: str,
    output: Path,
) -> None:
    operations = (
        CERTIFICATE_OPERATIONS
        if benchmark_type == "certificate"
        else KEM_OPERATIONS
    )
    operation_fields = [field for field, _ in operations]
    headers = [
        "Algorithm",
        "NIST",
        *(label for _, label in operations),
        "Total (s)",
        "Peak memory (KB)",
        "Output (B)",
        "Success",
        "Status",
    ]
    alignment = "l" + "r" * (len(headers) - 2) + "l"
    lines = [
        "% Requires \\usepackage{booktabs} and \\usepackage{graphicx}",
        "\\begin{table}[htbp]",
        "\\centering",
        "\\small",
        "\\setlength{\\tabcolsep}{4pt}",
        f"\\caption{{On-device {benchmark_type} benchmark}}",
        f"\\label{{tab:{latex_label(run_id)}}}",
        "\\resizebox{\\textwidth}{!}{%",
        f"\\begin{{tabular}}{{{alignment}}}",
        "\\toprule",
        " & ".join(headers) + r" \\",
        "\\midrule",
    ]
    for row in rows:
        values = [
            latex_escape(row["algorithm"]),
            latex_escape(row.get("nist_level", "") or "--"),
            *(
                latex_number(row.get(field), decimals=3)
                for field in operation_fields
            ),
            latex_number(row.get("mean_time_seconds"), decimals=3),
            latex_number(row.get("peak_memory_kb"), decimals=3),
            latex_number(row.get("generated_output_bytes"), decimals=3),
            f"{row['success_count']}/{row['attempt_count']}",
            latex_escape(row["status"]),
        ]
        lines.append(" & ".join(values) + r" \\")
    lines.extend(
        [
            "\\bottomrule",
            "\\end{tabular}",
            "}",
            "\\end{table}",
            "",
        ]
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines))


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    run_dir = resolve_run_dir(args.run)
    benchmark_type = detect_benchmark_type(run_dir)
    attempts = read_attempts(run_dir)
    rows = (
        aggregate_certificate_rows(attempts)
        if benchmark_type == "certificate"
        else aggregate_kem_rows(attempts)
    )
    out_dir = (args.out_dir or OUTPUT_ROOT / run_dir.name).resolve()
    stem = f"{benchmark_type}_device_summary"
    graph = out_dir / f"{stem}.{args.format}"
    table = out_dir / f"{benchmark_type}_device_operations.tex"

    plot_summary(
        rows,
        benchmark_type=benchmark_type,
        run_id=run_dir.name,
        output=graph,
        logarithmic_time=not args.linear_time,
    )
    write_latex_table(
        rows,
        benchmark_type=benchmark_type,
        run_id=run_dir.name,
        output=table,
    )

    measured = sum(row["success_count"] > 0 for row in rows)
    print(f"type={benchmark_type}")
    print(f"algorithms={len(rows)}")
    print(f"measured_algorithms={measured}")
    print(f"graph={graph}")
    print(f"table={table}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
