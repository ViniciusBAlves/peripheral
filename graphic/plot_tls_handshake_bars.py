#!/usr/bin/env python3
"""Plot TLS handshake bar charts from a benchmark result directory."""

from __future__ import annotations

import argparse
import csv
import math
import statistics
from collections import defaultdict
from pathlib import Path

try:
    import matplotlib.pyplot as plt
    from matplotlib.colors import LinearSegmentedColormap
    import numpy as np
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Missing Python plotting dependency. On Arch/CachyOS, install it with:\n"
        "  sudo pacman -S python-matplotlib python-numpy\n"
        "or use a virtualenv with:\n"
        "  python -m pip install matplotlib numpy"
    ) from exc


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS_ROOT = PROJECT_ROOT / "benchmarking" / "results"

PURE_PQC_KEM_PREFIXES = ("MLKEM",)
HYBRID_KEM_PREFIXES = ("SecP", "X25519MLKEM")
PQC_SIG_PREFIXES = ("ML-DSA", "SLH-DSA")
SECURITY_LEVELS = (1, 3, 5)
HANDSHAKE_HEATMAP_MAX_MS = 6000
HEATMAP_CMAP = LinearSegmentedColormap.from_list(
    "benchmark_green_to_red",
    ("#15803d", "#facc15", "#b91c1c"),
)
T_CRITICAL_95 = (
    0.0,
    12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262,
    2.228, 2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101,
    2.093, 2.086, 2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052,
    2.048, 2.045, 2.042,
)


def resolve_run_dir(value: str) -> Path:
    path = Path(value).expanduser()
    if path.exists():
        return path.resolve()

    candidate = DEFAULT_RESULTS_ROOT / value
    if candidate.exists():
        return candidate.resolve()

    raise FileNotFoundError(
        f"Benchmark result directory not found: {value}. "
        f"Tried {path} and {candidate}."
    )


def is_pqc_or_hybrid_kem(kex_group: str) -> bool:
    return is_pure_pqc_kem(kex_group) or is_hybrid_kem(kex_group)


def is_pure_pqc_kem(kex_group: str) -> bool:
    return kex_group.startswith(PURE_PQC_KEM_PREFIXES)


def is_hybrid_kem(kex_group: str) -> bool:
    return kex_group.startswith(HYBRID_KEM_PREFIXES)


def is_pqc_signature(cert_sig_alg: str) -> bool:
    return cert_sig_alg.startswith(PQC_SIG_PREFIXES)


def case_category(row: dict[str, str]) -> str:
    kex = row.get("kex_group", "")
    signature_is_pqc = is_pqc_signature(row.get("cert_sig_alg", ""))
    if is_hybrid_kem(kex):
        return "mixed"
    if is_pure_pqc_kem(kex) and signature_is_pqc:
        return "pqc_only"
    if not is_pqc_or_hybrid_kem(kex) and not signature_is_pqc:
        return "classic_only"
    return "mixed"


def heatmap_axes_by_descending_mean(
    values_by_pair: dict[tuple[str, str], list[float]],
) -> tuple[list[str], list[str]]:
    values_by_kem: dict[str, list[float]] = defaultdict(list)
    values_by_signature: dict[str, list[float]] = defaultdict(list)
    for (kem, signature), values in values_by_pair.items():
        values_by_kem[kem].extend(values)
        values_by_signature[signature].extend(values)

    # imshow places row zero at the top. Rows therefore descend, while columns
    # ascend from left to right so the largest KEM mean is at the right edge.
    kems = sorted(
        values_by_kem,
        key=lambda kem: (statistics.mean(values_by_kem[kem]), kem.lower()),
    )
    signatures = sorted(
        values_by_signature,
        key=lambda signature: (
            -statistics.mean(values_by_signature[signature]),
            signature.lower(),
        ),
    )
    return kems, signatures


def float_or_none(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def int_or_none(value: str | None) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError:
        return None


def normalize_security_level(level: int | None) -> int | None:
    if level is None:
        return None
    if level <= 2:
        return 1
    if level <= 3:
        return 3
    return 5


def kem_security_level(row: dict[str, str]) -> int | None:
    return normalize_security_level(int_or_none(row.get("kex_nist_level")))


def handshake_value(row: dict[str, str]) -> float | None:
    return float_or_none(
        row.get("mean_raw_handshake_ms") or row.get("mean_handshake_ms")
    )


def ci95_half_width(row: dict[str, str]) -> float | None:
    stddev = float_or_none(
        row.get("stddev_raw_handshake_ms") or row.get("stddev_handshake_ms")
    )
    sample_count = int_or_none(row.get("success_count"))
    if stddev is None or sample_count is None or sample_count < 2:
        return None
    degrees_of_freedom = sample_count - 1
    critical = (
        T_CRITICAL_95[degrees_of_freedom]
        if degrees_of_freedom < len(T_CRITICAL_95)
        else 1.96
    )
    return critical * stddev / math.sqrt(sample_count)


def load_from_summary(summary_csv: Path) -> list[dict[str, str]]:
    if not summary_csv.exists():
        return []
    with summary_csv.open(newline="") as fp:
        rows = list(csv.DictReader(fp))
    normalized: list[dict[str, str]] = []
    for row in rows:
        value = handshake_value(row)
        if value is None:
            continue
        row["mean_handshake_ms"] = f"{value:.3f}"
        normalized.append(row)
    return normalized


def load_from_attempts(run_dir: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for attempts_csv in sorted((run_dir / "cases").glob("*/attempts.csv")):
        with attempts_csv.open(newline="") as fp:
            attempts = list(csv.DictReader(fp))
        successes = [
            row
            for row in attempts
            if row.get("status") == "success"
            and row.get("warmup") != "1"
            and float_or_none(
                row.get("raw_handshake_ms") or row.get("tls_handshake_ms")
            ) is not None
        ]
        if not successes:
            continue

        first = successes[0]
        values = [
            float(row.get("raw_handshake_ms") or row["tls_handshake_ms"])
            for row in successes
        ]
        stddev = statistics.stdev(values) if len(values) > 1 else 0.0
        rows.append(
            {
                "case_id": attempts_csv.parent.name.split("_", 1)[-1],
                "kex_group": first.get("kex_group", ""),
                "kex_nist_level": first.get("kex_nist_level", ""),
                "cert_sig_alg": first.get("cert_sig_alg", ""),
                "sig_nist_level": first.get("sig_nist_level", ""),
                "mean_handshake_ms": f"{statistics.mean(values):.3f}",
                "stddev_raw_handshake_ms": f"{stddev:.3f}",
                "success_count": str(len(successes)),
            }
        )
    return rows


def add_attempt_cpu_peaks(rows: list[dict[str, str]], run_dir: Path) -> None:
    rows_by_case = {row.get("case_id", ""): row for row in rows}
    for attempts_csv in sorted((run_dir / "cases").glob("*/attempts.csv")):
        case_id = attempts_csv.parent.name.split("_", 1)[-1]
        target = rows_by_case.get(case_id)
        if target is None:
            continue
        with attempts_csv.open(newline="") as fp:
            attempts = csv.DictReader(fp)
            values = [
                value
                for attempt in attempts
                if attempt.get("status") == "success"
                and attempt.get("warmup") != "1"
                and (
                    value := float_or_none(
                        attempt.get("system_cpu_usage_percent")
                    )
                ) is not None
            ]
        if values:
            target["peak_system_cpu_usage_percent"] = f"{max(values):.3f}"


def load_rows(run_dir: Path) -> list[dict[str, str]]:
    rows = load_from_summary(run_dir / "summary.csv")
    if rows:
        add_attempt_cpu_peaks(rows, run_dir)
        return rows
    rows = load_from_attempts(run_dir)
    add_attempt_cpu_peaks(rows, run_dir)
    return rows


def short_label(row: dict[str, str]) -> str:
    kex = row.get("kex_group", "")
    sig = row.get("cert_sig_alg", "")
    return f"{kex}\n{sig}"


def plot_group(rows: list[dict[str, str]], title: str, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = sorted(rows, key=lambda row: float(row["mean_handshake_ms"]), reverse=True)

    count = len(rows)
    fig_width = max(12, min(44, count * 0.48))
    label_font = 14 if count <= 24 else 12 if count <= 48 else 10
    value_font = max(4, label_font - 1)
    fig, ax = plt.subplots(figsize=(fig_width, 8.5), constrained_layout=True)

    labels = [short_label(row) for row in rows]
    values = [float(row["mean_handshake_ms"]) for row in rows]
    errors = [ci95_half_width(row) or 0.0 for row in rows]
    colors = plt.cm.inferno(np.linspace(0.15, 0.9, len(values)))
    bars = ax.bar(
        range(len(values)),
        values,
        width=1.0,
        color=colors,
        edgecolor="#1a1a1a",
        linewidth=0.25,
        yerr=errors,
        error_kw={
            "ecolor": "#111111",
            "elinewidth": 0.8,
            "capsize": 2.0,
            "capthick": 0.8,
        },
    )

    ax.set_title(title)
    ax.set_ylabel("TLS handshake mean (ms), with 95% CI")
    ax.set_xlabel("KEM / certificate signature")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=72, ha="right", fontsize=label_font)
    ax.set_xlim(-0.5, len(values) - 0.5)
    ax.margins(x=0)
    ax.grid(axis="y", linestyle=":", alpha=0.35)

    for bar, value in zip(bars, values):
        ax.annotate(
            f"{value:.0f}",
            xy=(bar.get_x() + bar.get_width() / 2, bar.get_height()),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=value_font,
        )

    fig.savefig(output, dpi=180)
    plt.close(fig)


def plot_security_levels(
    rows: list[dict[str, str]],
    title_prefix: str,
    filename_prefix: str,
    out_dir: Path,
    run_id: str,
    extension: str,
) -> dict[int, int]:
    counts: dict[int, int] = {}
    for level in SECURITY_LEVELS:
        level_rows = [row for row in rows if kem_security_level(row) == level]
        counts[level] = len(level_rows)
        if level_rows:
            plot_group(
                level_rows,
                f"{title_prefix} - NIST level {level} - {run_id}",
                out_dir / f"{filename_prefix}_nist_level_{level}.{extension}",
            )
    return counts


def plot_heatmap(rows: list[dict[str, str]], output: Path, run_id: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    values_by_pair: dict[tuple[str, str], list[float]] = defaultdict(list)
    ci_by_pair: dict[tuple[str, str], list[float]] = defaultdict(list)
    for row in rows:
        kex = row.get("kex_group", "")
        sig = row.get("cert_sig_alg", "")
        value = handshake_value(row)
        if kex and sig and value is not None:
            values_by_pair[(kex, sig)].append(value)
            ci = ci95_half_width(row)
            if ci is not None:
                ci_by_pair[(kex, sig)].append(ci)

    if not values_by_pair:
        raise SystemExit("No KEM/signature handshake values found for heatmap")

    kems, sigs = heatmap_axes_by_descending_mean(values_by_pair)
    matrix = np.full((len(sigs), len(kems)), np.nan)
    ci_matrix = np.full((len(sigs), len(kems)), np.nan)
    for row_idx, sig in enumerate(sigs):
        for col_idx, kex in enumerate(kems):
            pair_values = values_by_pair.get((kex, sig))
            if pair_values:
                matrix[row_idx, col_idx] = statistics.mean(pair_values)
                pair_ci = ci_by_pair.get((kex, sig))
                if pair_ci:
                    ci_matrix[row_idx, col_idx] = statistics.mean(pair_ci)

    masked = np.ma.masked_invalid(matrix)
    cmap = HEATMAP_CMAP.copy()
    cmap.set_bad("#f1f1f1")
    fig, ax = plt.subplots(
        figsize=(max(10, len(kems) * 0.9), max(7, len(sigs) * 0.55)),
        constrained_layout=True,
    )
    image = ax.imshow(
        masked,
        cmap=cmap,
        aspect="auto",
        vmin=0,
        vmax=HANDSHAKE_HEATMAP_MAX_MS,
    )
    ax.set_title(f"TLS handshake mean w/ 95% confidence - {run_id}")
    ax.set_xlabel("KEM / TLS key exchange group")
    ax.set_ylabel("Certificate signature algorithm")
    ax.set_xticks(range(len(kems)))
    ax.set_yticks(range(len(sigs)))
    ax.set_xticklabels(kems, rotation=55, ha="right", fontsize=7)
    ax.set_yticklabels(sigs, fontsize=7)
    median = np.nanmedian(matrix)
    for row_idx in range(len(sigs)):
        for col_idx in range(len(kems)):
            value = matrix[row_idx, col_idx]
            if not np.isnan(value):
                ci = ci_matrix[row_idx, col_idx]
                annotation = (
                    f"{value:.0f}\n±{ci:.0f}"
                    if not np.isnan(ci)
                    else f"{value:.0f}"
                )
                ax.text(
                    col_idx, row_idx, annotation,
                    ha="center", va="center", fontsize=12,
                    color="white" if value <= median else "black",
                )
    colorbar = fig.colorbar(image, ax=ax, extend="max")
    colorbar.set_label("TLS handshake mean (ms); cells show mean ± 95% CI")
    fig.savefig(output, dpi=180)
    plt.close(fig)


def plot_percent_heatmap(
    rows: list[dict[str, str]],
    metric: str,
    title: str,
    output: Path,
    *,
    value_suffix: str = "%",
    value_decimals: int = 1,
    colorbar_label: str = "Peak usage (%)",
    vmin: float | None = 0,
    vmax: float | None = 100,
) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    values_by_pair: dict[tuple[str, str], list[float]] = defaultdict(list)
    for row in rows:
        kex = row.get("kex_group", "")
        sig = row.get("cert_sig_alg", "")
        value = float_or_none(row.get(metric))
        if kex and sig and value is not None:
            values_by_pair[(kex, sig)].append(value)

    if not values_by_pair:
        print(f"warning: no values found for {metric}")
        return 0

    kems, sigs = heatmap_axes_by_descending_mean(values_by_pair)
    matrix = np.full((len(sigs), len(kems)), np.nan)
    for row_idx, sig in enumerate(sigs):
        for col_idx, kex in enumerate(kems):
            pair_values = values_by_pair.get((kex, sig))
            if pair_values:
                matrix[row_idx, col_idx] = statistics.mean(pair_values)

    masked = np.ma.masked_invalid(matrix)
    cmap = HEATMAP_CMAP.copy()
    cmap.set_bad("#f1f1f1")
    fig, ax = plt.subplots(
        figsize=(max(10, len(kems) * 0.9), max(7, len(sigs) * 0.55)),
        constrained_layout=True,
    )
    image = ax.imshow(masked, cmap=cmap, aspect="auto", vmin=vmin, vmax=vmax)
    ax.set_title(title)
    ax.set_xlabel("KEM / TLS key exchange group")
    ax.set_ylabel("Certificate signature algorithm")
    ax.set_xticks(range(len(kems)))
    ax.set_yticks(range(len(sigs)))
    ax.set_xticklabels(kems, rotation=55, ha="right", fontsize=7)
    ax.set_yticklabels(sigs, fontsize=7)
    for row_idx in range(len(sigs)):
        for col_idx in range(len(kems)):
            value = matrix[row_idx, col_idx]
            if not np.isnan(value):
                ax.text(
                    col_idx, row_idx,
                    f"{value:.{value_decimals}f}{value_suffix}",
                    ha="center", va="center", fontsize=12,
                    color="white" if image.norm(value) < 0.6 else "black",
                )
    colorbar = fig.colorbar(image, ax=ax)
    colorbar.set_label(colorbar_label)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return len(values_by_pair)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "run_dir",
        help="Benchmark result directory or run id under benchmarking/results, e.g. 20260620_230500_123",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=None,
        help="Output directory for PNG files. Defaults to graphic/out/<run_id>.",
    )
    parser.add_argument(
        "--sec-levels",
        action="store_true",
        help="Also split each category by KEM NIST level (2 is grouped with 1).",
    )
    parser.add_argument(
        "--heatmap",
        action="store_true",
        help="Also generate a KEM by certificate-signature handshake heatmap.",
    )
    parser.add_argument(
        "--skip-rsa-pss",
        action="store_true",
        help=(
            "Exclude RSA-PSS-15360 from all bar charts, including NIST-level "
            "charts. "
            "Heatmaps keep the complete data set."
        ),
    )
    parser.add_argument(
        "--generate-png",
        action="store_true",
        help="Generate PNG images instead of the default vector PDF files.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    run_dir = resolve_run_dir(args.run_dir)
    rows = load_rows(run_dir)
    if not rows:
        raise SystemExit(f"No successful TLS handshake rows found in {run_dir}")

    plot_rows = (
        [
            row for row in rows
            if row.get("cert_sig_alg") != "RSA-PSS-15360"
        ]
        if args.skip_rsa_pss
        else rows
    )
    categories = {
        "pqc_only": [
            row for row in plot_rows if case_category(row) == "pqc_only"
        ],
        "classic_only": [
            row for row in plot_rows if case_category(row) == "classic_only"
        ],
        "mixed": [row for row in plot_rows if case_category(row) == "mixed"],
    }

    out_dir = args.out_dir or (PROJECT_ROOT / "graphic" / "out" / run_dir.name)
    extension = "png" if args.generate_png else "pdf"
    chart_config = {
        "pqc_only": ("PQC-only TLS handshakes", "tls_handshake_pqc_only"),
        "classic_only": (
            "Classic-only TLS handshakes", "tls_handshake_classic_only"
        ),
        "mixed": ("Mixed / hybrid TLS handshakes", "tls_handshake_mixed"),
    }
    for category, category_rows in categories.items():
        if not category_rows:
            continue
        title, filename = chart_config[category]
        plot_group(
            category_rows,
            f"{title} - {run_dir.name}",
            out_dir / f"{filename}.{extension}",
        )
        if args.sec_levels:
            counts = plot_security_levels(
                category_rows, title, filename, out_dir, run_dir.name,
                extension,
            )
            for level in SECURITY_LEVELS:
                print(
                    f"{category}_nist_level_{level}={counts.get(level, 0)}"
                )

    if args.heatmap:
        plot_heatmap(
            rows,
            out_dir / f"tls_handshake_heatmap.{extension}",
            run_dir.name,
        )
        hardware_heatmaps = (
            (
                "peak_system_cpu_usage_percent",
                f"Peak observed system CPU usage - {run_dir.name}",
                "heatmap_cpu_peak_usage_percent",
            ),
            (
                "max_client_heap_peak_usage_percent",
                f"Peak wolfSSL heap usage - {run_dir.name}",
                "heatmap_heap_peak_usage_percent",
            ),
            (
                "firmware_static_ram_usage_percent",
                f"Firmware static RAM usage - {run_dir.name}",
                "heatmap_static_ram_usage_percent",
            ),
            (
                "max_thread_stack_peak_percent",
                f"Peak thread stack usage - {run_dir.name}",
                "heatmap_thread_stack_peak_percent",
            ),
        )
        for metric, title, filename_prefix in hardware_heatmaps:
            plotted = plot_percent_heatmap(
                rows, metric, title,
                out_dir / f"{filename_prefix}.{extension}",
            )
            print(f"{metric}_heatmap_cells={plotted}")
        heap_bytes_cells = plot_percent_heatmap(
            rows,
            "max_client_heap_peak_bytes",
            f"Peak wolfSSL heap allocation in bytes - {run_dir.name}",
            out_dir / f"heatmap_client_heap_peak_bytes.{extension}",
            value_suffix="",
            value_decimals=0,
            colorbar_label="Peak wolfSSL heap allocation (bytes)",
            vmin=None,
            vmax=None,
        )
        print(f"max_client_heap_peak_bytes_heatmap_cells={heap_bytes_cells}")
        print("heatmaps=6")

    print(f"rows={len(rows)}")
    print(f"bar_chart_rows={len(plot_rows)}")
    print(f"format={extension}")
    for category, category_rows in categories.items():
        print(f"{category}={len(category_rows)}")
    print(f"out_dir={out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())