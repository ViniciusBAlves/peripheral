#!/usr/bin/env python3
"""Compare two benchmark runs with KEM-by-certificate difference heatmaps."""

from __future__ import annotations

import argparse
from pathlib import Path

try:
    import matplotlib.pyplot as plt
    from matplotlib.colors import LinearSegmentedColormap
    import numpy as np
except ModuleNotFoundError as exc:
    raise SystemExit(
        "Missing plotting dependency. Install matplotlib and numpy with:\n"
        "  sudo pacman -S python-matplotlib python-numpy"
    ) from exc

from plot_tls_handshake_bars import (
    algorithm_label,
    float_or_none,
    heatmap_axes_by_descending_mean,
    kem_security_level,
    load_rows,
    resolve_run_dir,
    signature_security_level,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DIFFERENCE_CMAP = LinearSegmentedColormap.from_list(
    "benchmark_difference",
    ("#15803d", "#f7f7f7", "#b91c1c"),
)
METRICS = (
    (
        "mean_handshake_ms",
        "TLS handshake time difference",
        "tls_handshake_difference",
        "ms",
        0,
    ),
    (
        "max_client_heap_peak_bytes",
        "Peak wolfSSL heap allocation difference",
        "heap_peak_allocation_difference",
        "bytes",
        0,
    ),
    (
        "peak_system_cpu_usage_percent",
        "Peak system CPU usage difference",
        "cpu_peak_usage_difference",
        "percentage points",
        1,
    ),
    (
        "mean_communication_overhead_ms",
        "Communication overhead difference",
        "communication_overhead_difference",
        "ms",
        0,
    ),
    (
        "mean_client_signature_total_ms",
        "Client signature time difference",
        "client_signature_time_difference",
        "ms",
        0,
    ),
)


def rows_by_pair(rows: list[dict[str, str]]) -> dict[tuple[str, str], dict[str, str]]:
    return {
        (row.get("kex_group", ""), row.get("cert_sig_alg", "")): row
        for row in rows
        if row.get("kex_group") and row.get("cert_sig_alg")
    }


def metric_differences(
    first_rows: list[dict[str, str]],
    second_rows: list[dict[str, str]],
    metric: str,
) -> tuple[
    dict[tuple[str, str], list[float]],
    dict[tuple[str, str], dict[str, str]],
]:
    first = rows_by_pair(first_rows)
    second = rows_by_pair(second_rows)
    differences: dict[tuple[str, str], list[float]] = {}
    metadata: dict[tuple[str, str], dict[str, str]] = {}
    for pair in sorted(first.keys() & second.keys()):
        first_value = float_or_none(first[pair].get(metric))
        second_value = float_or_none(second[pair].get(metric))
        if first_value is None or second_value is None:
            continue
        differences[pair] = [first_value - second_value]
        metadata[pair] = first[pair]
    return differences, metadata


def plot_difference_heatmap(
    first_rows: list[dict[str, str]],
    second_rows: list[dict[str, str]],
    *,
    metric: str,
    title: str,
    unit: str,
    decimals: int,
    first_name: str,
    second_name: str,
    output: Path,
) -> int:
    values_by_pair, metadata = metric_differences(
        first_rows, second_rows, metric
    )
    if not values_by_pair:
        print(f"warning: no shared values found for {metric}")
        return 0

    kems, signatures = heatmap_axes_by_descending_mean(values_by_pair)
    matrix = np.full((len(signatures), len(kems)), np.nan)
    for row_idx, signature in enumerate(signatures):
        for col_idx, kem in enumerate(kems):
            values = values_by_pair.get((kem, signature))
            if values:
                matrix[row_idx, col_idx] = values[0]

    finite = np.abs(matrix[np.isfinite(matrix)])
    limit = float(finite.max()) if finite.size else 1.0
    if limit == 0.0:
        limit = 1.0

    cmap = DIFFERENCE_CMAP.copy()
    cmap.set_bad("#f1f1f1")
    fig, ax = plt.subplots(
        figsize=(
            max(10, len(kems) * 0.9),
            max(7, len(signatures) * 0.55),
        ),
        constrained_layout=True,
    )
    image = ax.imshow(
        np.ma.masked_invalid(matrix),
        cmap=cmap,
        aspect="auto",
        vmin=-limit,
        vmax=limit,
    )
    ax.set_title(
        f"{title}\n{first_name} minus {second_name}"
    )
    ax.set_xlabel("KEM / TLS key exchange group")
    ax.set_ylabel("Certificate signature algorithm")
    ax.set_xticks(range(len(kems)))
    ax.set_yticks(range(len(signatures)))

    kem_levels = {
        pair[0]: kem_security_level(row) for pair, row in metadata.items()
    }
    signature_levels = {
        pair[1]: signature_security_level(row)
        for pair, row in metadata.items()
    }
    ax.set_xticklabels(
        [algorithm_label(kem, kem_levels.get(kem)) for kem in kems],
        rotation=55,
        ha="right",
        fontsize=7,
    )
    ax.set_yticklabels(
        [
            algorithm_label(signature, signature_levels.get(signature))
            for signature in signatures
        ],
        fontsize=7,
    )

    for row_idx in range(len(signatures)):
        for col_idx in range(len(kems)):
            value = matrix[row_idx, col_idx]
            if np.isfinite(value):
                ax.text(
                    col_idx,
                    row_idx,
                    f"{value:+.{decimals}f}",
                    ha="center",
                    va="center",
                    fontsize=12,
                    color="black",
                )

    colorbar = fig.colorbar(image, ax=ax)
    colorbar.set_label(
        f"Difference ({unit}): input 1 - input 2"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return len(values_by_pair)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "input_1",
        help="First benchmark result directory or id.",
    )
    parser.add_argument(
        "input_2",
        help="Second benchmark result directory or id.",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        help="Output directory. Defaults to graphic/out/comparison_<run1>_vs_<run2>.",
    )
    parser.add_argument(
        "--generate-png",
        action="store_true",
        help="Generate PNG instead of the default vector PDF files.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    first_dir = resolve_run_dir(args.input_1)
    second_dir = resolve_run_dir(args.input_2)
    first_rows = load_rows(first_dir)
    second_rows = load_rows(second_dir)
    if not first_rows:
        raise SystemExit(f"No successful benchmark rows found in {first_dir}")
    if not second_rows:
        raise SystemExit(f"No successful benchmark rows found in {second_dir}")

    output_dir = args.out_dir or (
        PROJECT_ROOT
        / "graphic"
        / "out"
        / f"comparison_{first_dir.name}_vs_{second_dir.name}"
    )
    extension = "png" if args.generate_png else "pdf"
    for metric, title, filename, unit, decimals in METRICS:
        cells = plot_difference_heatmap(
            first_rows,
            second_rows,
            metric=metric,
            title=title,
            unit=unit,
            decimals=decimals,
            first_name=first_dir.name,
            second_name=second_dir.name,
            output=output_dir / f"{filename}.{extension}",
        )
        print(f"{metric}_shared_cells={cells}")

    print(f"input_1={first_dir}")
    print(f"input_2={second_dir}")
    print(f"output={output_dir}")
    print(f"format={extension}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
