#!/usr/bin/env python3
"""Plot handshake, client KEM, and client signature energy by benchmark case."""

from __future__ import annotations

import argparse
import csv
import statistics
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

from plot_tls_handshake_bars import (
    HEATMAP_CMAP,
    algorithm_label,
    case_category,
    heatmap_axes_by_descending_mean,
    kem_security_level,
    signature_security_level,
)


ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "benchmarking" / "results"


def resolve_run_dir(value: str) -> Path:
    path = Path(value).expanduser()
    if path.is_dir():
        return path.resolve()
    candidate = RESULTS / value
    if candidate.is_dir():
        return candidate.resolve()
    raise FileNotFoundError(f"Benchmark result directory not found: {value}")


def number(row: dict[str, str], field: str) -> float | None:
    value = row.get(field, "")
    if value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def nist_level(row: dict[str, str], field: str) -> str:
    try:
        level = int(row.get(field, ""))
    except ValueError:
        return "?"
    return "1" if level <= 2 else "3" if level <= 3 else "5"


def algorithm_label(name: str, level: str) -> str:
    return f"[{level}] - {name}"


def load_rows(run_dir: Path) -> list[dict[str, str]]:
    summary = run_dir / "summary.csv"
    if summary.exists():
        with summary.open(newline="") as stream:
            rows = list(csv.DictReader(stream))
        rows = [
            row for row in rows
            if row.get("success_count", "0") not in {"", "0"}
            and number(row, "mean_handshake_energy_uj") is not None
        ]
        add_energy_confidence_intervals(rows, run_dir)
        return rows

    rows: list[dict[str, str]] = []
    for attempts_path in sorted((run_dir / "cases").glob("*/attempts.csv")):
        with attempts_path.open(newline="") as stream:
            attempts = [
                row for row in csv.DictReader(stream)
                if row.get("status") == "success"
                and row.get("warmup") != "1"
            ]
        if not attempts:
            continue
        first = attempts[0]
        result = dict(first)
        result["case_id"] = attempts_path.parent.name.split("_", 1)[-1]
        for output, input_field in (
            ("mean_handshake_energy_uj", "handshake_energy_uj"),
            ("mean_client_kem_energy_uj", "client_kem_energy_uj"),
            ("mean_client_signature_energy_uj", "client_signature_energy_uj"),
        ):
            values = [number(row, input_field) for row in attempts]
            values = [value for value in values if value is not None]
            result[output] = f"{statistics.mean(values):.6f}" if values else ""
        result["success_count"] = str(len(attempts))
        add_energy_confidence_intervals([result], run_dir)
        rows.append(result)
    return rows


T_CRITICAL_95 = (
    0.0, 12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365,
    2.306, 2.262, 2.228, 2.201, 2.179, 2.160, 2.145, 2.131,
    2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069,
    2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042,
)


def confidence_half_width(values: list[float]) -> float | None:
    if len(values) < 2:
        return None
    critical = (
        T_CRITICAL_95[len(values) - 1]
        if len(values) - 1 < len(T_CRITICAL_95)
        else 1.96
    )
    return critical * statistics.stdev(values) / len(values) ** 0.5


def add_energy_confidence_intervals(
    rows: list[dict[str, str]], run_dir: Path
) -> None:
    rows_by_case = {row.get("case_id", ""): row for row in rows}
    fields = (
        "handshake_energy_uj",
        "client_kem_energy_uj",
        "client_signature_energy_uj",
    )
    for attempts_path in sorted((run_dir / "cases").glob("*/attempts.csv")):
        case_id = attempts_path.parent.name.split("_", 1)[-1]
        target = rows_by_case.get(case_id)
        if target is None:
            continue
        with attempts_path.open(newline="") as stream:
            attempts = list(csv.DictReader(stream))
        for field in fields:
            values = [
                number(row, field) for row in attempts
                if row.get("status") == "success"
                and row.get("warmup") != "1"
            ]
            values = [value for value in values if value is not None]
            ci = confidence_half_width(values)
            if ci is not None:
                target[f"ci_{field}"] = f"{ci:.6f}"


def handshake_energy_components(row: dict[str, str]) -> tuple[float, float, float]:
    """Return disjoint energy components whose sum is total handshake energy."""
    total = number(row, "mean_handshake_energy_uj") or 0.0
    kem = number(row, "mean_client_kem_energy_uj") or 0.0
    signature = number(row, "mean_client_signature_energy_uj") or 0.0
    measured = kem + signature

    # Normalize defensively if nested or noisy GPIO windows exceed the total.
    if measured > total and measured > 0.0:
        scale = total / measured
        kem *= scale
        signature *= scale

    remaining = max(0.0, total - kem - signature)
    return kem / 1000.0, signature / 1000.0, remaining / 1000.0


def plot_heatmap(
    rows: list[dict[str, str]],
    metric: str,
    output: Path,
    run_id: str,
    title: str,
) -> int:
    values_by_pair: dict[tuple[str, str], list[float]] = {}
    ci_by_pair: dict[tuple[str, str], float] = {}
    for row in rows:
        kem = row.get("kex_group", "")
        signature = row.get("cert_sig_alg", "")
        value = number(row, metric)
        if kem and signature and value is not None:
            values_by_pair.setdefault((kem, signature), []).append(value / 1000.0)
            ci = number(row, f"ci_{metric.removeprefix('mean_')}")
            if ci is not None:
                ci_by_pair[(kem, signature)] = ci / 1000.0
    if not values_by_pair:
        print(f"warning: no values found for {metric}")
        return 0

    kems, signatures = heatmap_axes_by_descending_mean(values_by_pair)
    matrix = np.full((len(signatures), len(kems)), np.nan)
    ci_matrix = np.full_like(matrix, np.nan)
    for row_index, signature in enumerate(signatures):
        for column_index, kem in enumerate(kems):
            values = values_by_pair.get((kem, signature))
            if values:
                matrix[row_index, column_index] = statistics.mean(values)
                ci = ci_by_pair.get((kem, signature))
                if ci is not None:
                    ci_matrix[row_index, column_index] = ci

    masked = np.ma.masked_invalid(matrix)
    cmap = HEATMAP_CMAP.copy()
    cmap.set_bad("#f1f1f1")
    fig, ax = plt.subplots(
        figsize=(max(10, len(kems) * 0.9), max(7, len(signatures) * 0.55)),
        constrained_layout=True,
    )
    image = ax.imshow(masked, cmap=cmap, aspect="auto", vmin=0)
    ax.set_title(f"{title} - {run_id}")
    ax.set_xlabel("KEM / TLS key exchange group")
    ax.set_ylabel("Certificate signature algorithm")
    ax.set_xticks(range(len(kems)))
    ax.set_yticks(range(len(signatures)))
    kem_levels = {row.get("kex_group", ""): kem_security_level(row) for row in rows}
    sig_levels = {
        row.get("cert_sig_alg", ""): signature_security_level(row)
        for row in rows
    }
    ax.set_xticklabels(
        [algorithm_label(kem, kem_levels.get(kem)) for kem in kems],
        rotation=55, ha="right", fontsize=7,
    )
    ax.set_yticklabels(
        [algorithm_label(signature, sig_levels.get(signature)) for signature in signatures],
        fontsize=7,
    )
    median = np.nanmedian(matrix)
    for row_index in range(len(signatures)):
        for column_index in range(len(kems)):
            value = matrix[row_index, column_index]
            if np.isnan(value):
                continue
            ci = ci_matrix[row_index, column_index]
            annotation = (
                f"{value:.2f}\n±{ci:.2f}"
                if not np.isnan(ci) else f"{value:.2f}"
            )
            ax.text(
                column_index, row_index, annotation,
                ha="center", va="center", fontsize=11,
                color="black",
            )
    colorbar = fig.colorbar(image, ax=ax)
    colorbar.set_label("Mean energy (mJ); avg ± 95% CI")
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return len(values_by_pair)


def plot(
    rows: list[dict[str, str]], output: Path, run_id: str, category: str
) -> int:
    rows = sorted(
        rows,
        key=lambda row: (
            -float(row["mean_handshake_energy_uj"]),
            row.get("case_id", "").lower(),
        ),
    )
    if not rows:
        raise SystemExit(f"No successful energy measurements found in {run_id}")

    labels = [
        f"{algorithm_label(row.get('kex_group', ''), nist_level(row, 'kex_nist_level'))}\n"
        f"{algorithm_label(row.get('cert_sig_alg', ''), nist_level(row, 'sig_nist_level'))}"
        for row in rows
    ]
    # Source CSV values are in microjoules. The three disjoint components are
    # displayed as one stacked bar whose height is total handshake energy.
    components = [handshake_energy_components(row) for row in rows]
    totals = np.asarray([
        (number(row, "mean_handshake_energy_uj") or 0.0) / 1000.0
        for row in rows
    ])
    errors = np.asarray([
        (number(row, "ci_handshake_energy_uj") or 0.0) / 1000.0
        for row in rows
    ])
    positions = np.arange(len(rows))
    fig_width = max(12.0, min(44.0, len(rows) * 0.48))
    fig, ax = plt.subplots(
        figsize=(fig_width, 9.0),
        constrained_layout=True,
    )
    colors = ("#2a9d8f", "#e9c46a", "#457b9d")
    names = ("Client KEM", "Client digital signature", "Remaining TLS handshake")
    bottoms = np.zeros(len(rows))
    top_bars = None
    for index, (name, color) in enumerate(zip(names, colors)):
        heights = np.asarray([parts[index] for parts in components])
        top_bars = ax.bar(
            positions,
            heights,
            width=1.0,
            bottom=bottoms,
            label=name,
            color=color,
            edgecolor="#1a1a1a",
            linewidth=0.25,
        )
        bottoms += heights

    ax.errorbar(
        positions,
        totals,
        yerr=errors,
        fmt="none",
        ecolor="#111111",
        elinewidth=0.8,
        capsize=2.0,
        capthick=0.8,
        zorder=5,
    )

    assert top_bars is not None
    for bar, value in zip(top_bars, totals):
        ax.annotate(
            f"{value:.2f}",
            (bar.get_x() + bar.get_width() / 2, value),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=10,
        )
    category_titles = {
        "pqc_only": "PQC-only",
        "classic_only": "Classic-only",
        "mixed": "Mixed / hybrid",
    }
    ax.set_title(
        f"Energy consumption by TLS case ({category_titles[category]}) - {run_id}"
    )
    ax.set_ylabel("Mean TLS handshake energy (mJ), with 95% CI")
    ax.set_xlabel("KEM / certificate signature")
    ax.set_xticks(positions)
    ax.set_xticklabels(labels, rotation=65, ha="right", fontsize=8)
    ax.set_xlim(-0.5, len(rows) - 0.5)
    ax.margins(x=0)
    ax.grid(axis="y", linestyle=":", alpha=0.35)
    ax.legend(loc="upper right")
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return len(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", help="run directory or run id")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="output directory; defaults to graphic/out/<run_id>",
    )
    parser.add_argument(
        "--generate-png",
        action="store_true",
        help="generate PNG instead of the default PDF",
    )
    parser.add_argument(
        "--heatmap",
        action="store_true",
        help="also generate three KEM × signature energy heatmaps",
    )
    args = parser.parse_args()
    run_dir = resolve_run_dir(args.run_dir)
    rows = load_rows(run_dir)
    extension = "png" if args.generate_png else "pdf"
    out_dir = args.out_dir or ROOT / "graphic" / "out" / run_dir.name
    categories = {
        "pqc_only": [row for row in rows if case_category(row) == "pqc_only"],
        "classic_only": [
            row for row in rows if case_category(row) == "classic_only"
        ],
        "mixed": [row for row in rows if case_category(row) == "mixed"],
    }
    total = 0
    for category, category_rows in categories.items():
        if not category_rows:
            continue
        output = out_dir / f"energy_handshake_kem_signature_{category}.{extension}"
        count = plot(category_rows, output, run_dir.name, category)
        total += count
        print(f"{category}_cases={count}")
    if args.heatmap:
        heatmaps = (
            ("mean_handshake_energy_uj", "Total TLS handshake energy", "handshake"),
            ("mean_client_kem_energy_uj", "Client KEM energy", "client_kem"),
            (
                "mean_client_signature_energy_uj",
                "Client digital-signature energy",
                "client_signature",
            ),
        )
        for metric, title, suffix in heatmaps:
            cells = plot_heatmap(
                rows, metric,
                out_dir / f"energy_heatmap_{suffix}.{extension}",
                run_dir.name, title,
            )
            print(f"{suffix}_energy_heatmap_cells={cells}")
    print(f"format={extension}")
    print(f"cases={total}")
    print(f"out_dir={out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
