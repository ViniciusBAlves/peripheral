#!/usr/bin/env python3
"""Generate a compact LaTeX table from transfer benchmark energy results."""

from __future__ import annotations

import argparse
import csv
import statistics
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

from plot_tls_handshake_bars import (
    HEATMAP_CMAP,
    algorithm_label,
    heatmap_axes_by_descending_mean,
    kem_security_level,
    pki_category,
    pki_signature_label,
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


def latex_escape(value: str) -> str:
    replacements = {
        "\\": r"\textbackslash{}",
        "&": r"\&",
        "%": r"\%",
        "$": r"\$",
        "#": r"\#",
        "_": r"\_\allowbreak{}",
        "{": r"\{",
        "}": r"\}",
        "~": r"\textasciitilde{}",
        "^": r"\textasciicircum{}",
    }
    return "".join(replacements.get(character, character) for character in value)


def float_or_none(value: str) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def payload_label(payload_bytes: int) -> str:
    if payload_bytes < 1024:
        return f"{payload_bytes} B"
    kib = payload_bytes / 1024.0
    return f"{kib:g} KiB"


def energy_cell(row: dict[str, str] | None) -> str:
    if row is None:
        return "--"
    mean_uj = float_or_none(row.get("mean_transfer_energy_uj", ""))
    ci_uj = float_or_none(row.get("ci95_transfer_energy_uj", ""))
    if mean_uj is None:
        return "--"
    mean_mj = mean_uj / 1000.0
    if ci_uj is None:
        return f"{mean_mj:.3f}"
    return rf"{mean_mj:.3f} $\pm$ {ci_uj / 1000.0:.3f}"


def load_case_metadata(run_dir: Path) -> dict[str, dict[str, str]]:
    for filename in ("handshake_summary.csv", "input_cases.csv"):
        path = run_dir / filename
        if path.exists():
            with path.open(newline="") as stream:
                return {
                    row["case_id"]: row for row in csv.DictReader(stream)
                    if row.get("case_id")
                }
    raise FileNotFoundError(f"Case metadata not found in {run_dir}")


def load_transfer_summary(run_dir: Path) -> list[dict[str, str]]:
    path = run_dir / "transfer_summary.csv"
    if not path.exists():
        raise FileNotFoundError(f"Transfer summary not found: {path}")
    metadata = load_case_metadata(run_dir)
    with path.open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    for row in rows:
        for key, value in metadata.get(row.get("case_id", ""), {}).items():
            row.setdefault(key, value)
    return rows


def plot_transfer_metric_heatmap(
    rows: list[dict[str, str]], metric: str, ci_metric: str,
    output: Path, run_id: str, pki: str, direction: str, payload_bytes: int,
    *, divisor: float, decimals: int, colorbar_label: str,
    annotation_fontsize: int = 8,
) -> int:
    values_by_pair: dict[tuple[str, str], list[float]] = defaultdict(list)
    ci_by_pair: dict[tuple[str, str], list[float]] = defaultdict(list)
    selected_rows = [
        row for row in rows
        if pki_category(row) == pki
        and row.get("direction") == direction
        and int(row.get("payload_bytes", "0")) == payload_bytes
    ]
    for row in selected_rows:
        value = float_or_none(row.get(metric, ""))
        kem = row.get("kex_group", "")
        signature = pki_signature_label(row)
        if value is None or not kem or not signature:
            continue
        values_by_pair[(kem, signature)].append(value / divisor)
        ci = float_or_none(row.get(ci_metric, ""))
        if ci is not None:
            ci_by_pair[(kem, signature)].append(ci / divisor)
    if not values_by_pair:
        return 0

    kems, signatures = heatmap_axes_by_descending_mean(values_by_pair)
    matrix = np.full((len(signatures), len(kems)), np.nan)
    ci_matrix = np.full_like(matrix, np.nan)
    for row_index, signature in enumerate(signatures):
        for column_index, kem in enumerate(kems):
            values = values_by_pair.get((kem, signature))
            if values:
                matrix[row_index, column_index] = statistics.mean(values)
            cis = ci_by_pair.get((kem, signature))
            if cis:
                ci_matrix[row_index, column_index] = statistics.mean(cis)

    cmap = HEATMAP_CMAP.copy()
    cmap.set_bad("#f1f1f1")
    fig, ax = plt.subplots(
        figsize=(max(10, len(kems) * 0.9), max(7, len(signatures) * 0.55)),
        constrained_layout=True,
    )
    image = ax.imshow(np.ma.masked_invalid(matrix), cmap=cmap, aspect="auto")
    direction_label = (
        "Server to device" if direction == "server_to_device"
        else "Device to server"
    )
    ax.set_title(
        f"{colorbar_label.split(';')[0]} - {payload_label(payload_bytes)} - "
        f"{direction_label} - {pki.capitalize()} PKI - {run_id}"
    )
    ax.set_xlabel("KEM / TLS key exchange group")
    ax.set_ylabel("Certificate signature algorithm")
    ax.set_xticks(range(len(kems)))
    ax.set_yticks(range(len(signatures)))
    kem_levels = {
        row.get("kex_group", ""): kem_security_level(row) for row in selected_rows
    }
    signature_levels = {
        pki_signature_label(row): signature_security_level(row)
        for row in selected_rows
    }
    ax.set_xticklabels(
        [algorithm_label(kem, kem_levels.get(kem)) for kem in kems],
        rotation=55, ha="right", fontsize=7,
    )
    ax.set_yticklabels(
        [algorithm_label(sig, signature_levels.get(sig)) for sig in signatures],
        fontsize=7,
    )
    for row_index in range(len(signatures)):
        for column_index in range(len(kems)):
            value = matrix[row_index, column_index]
            if np.isnan(value):
                continue
            ci = ci_matrix[row_index, column_index]
            annotation = f"{value:.{decimals}f}"
            if not np.isnan(ci):
                annotation += f"\n±{ci:.{decimals}f}"
            ax.text(column_index, row_index, annotation,
                    ha="center", va="center",
                    fontsize=annotation_fontsize, color="black")
    fig.colorbar(image, ax=ax).set_label(colorbar_label)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return len(values_by_pair)


def load_transfer_attempts(run_dir: Path) -> list[dict[str, str]]:
    metadata = load_case_metadata(run_dir)
    rows: list[dict[str, str]] = []
    for path in sorted((run_dir / "cases").glob("*/transmissions.csv")):
        with path.open(newline="") as stream:
            attempts = list(csv.DictReader(stream))
        for row in attempts:
            if row.get("status") != "success":
                continue
            for key, value in metadata.get(row.get("case_id", ""), {}).items():
                row.setdefault(key, value)
            rows.append(row)
    return rows


def plot_transfer_time_energy_scatter(
    rows: list[dict[str, str]], output: Path, run_id: str,
) -> int:
    """Plot one mean time/energy point per case, direction, and payload size."""
    points: list[tuple[float, float, int, str]] = []
    for row in rows:
        time_ms = float_or_none(row.get("mean_end_to_end_ms", ""))
        energy_uj = float_or_none(row.get("mean_transfer_energy_uj", ""))
        payload = int(row.get("payload_bytes", "0"))
        direction = row.get("direction", "")
        if (time_ms is None or time_ms <= 0.0 or energy_uj is None
                or energy_uj <= 0.0 or payload <= 0):
            continue
        points.append((time_ms, energy_uj / 1000.0, payload, direction))
    if not points:
        return 0

    payloads = sorted({point[2] for point in points})
    colors = {
        payload: plt.colormaps["inferno"](position)
        for payload, position in zip(
            payloads, np.linspace(0.18, 0.82, len(payloads)), strict=True,
        )
    }
    markers = {"server_to_device": "o", "device_to_server": "^"}
    direction_labels = {
        "server_to_device": "Server to device",
        "device_to_server": "Device to server",
    }

    fig, ax = plt.subplots(figsize=(11.5, 7.5), constrained_layout=True)
    for payload in payloads:
        for direction, marker in markers.items():
            selected = [
                point for point in points
                if point[2] == payload and point[3] == direction
            ]
            if not selected:
                continue
            ax.scatter(
                [point[0] for point in selected],
                [point[1] for point in selected],
                s=30, marker=marker, color=colors[payload], alpha=0.72,
                edgecolors="white", linewidths=0.35,
                label=f"{payload_label(payload)} - {direction_labels[direction]}",
            )

    ax.set_title(f"Transfer energy vs end-to-end time - {run_id}")
    ax.set_xlabel("Mean end-to-end transfer time (ms)")
    ax.set_ylabel("Mean transfer energy (mJ)")
    ax.grid(linestyle=":", alpha=0.35)
    ax.legend(title="MQTT payload and direction", fontsize=8, ncol=2)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return len(points)


def plot_extra_bytes_heatmap(
    attempts: list[dict[str, str]], output: Path, run_id: str, pki: str,
) -> int:
    """Plot total bidirectional L2CAP bytes beyond each MQTT payload."""
    grouped: dict[tuple[str, str, int], list[float]] = defaultdict(list)
    for row in attempts:
        if pki_category(row) != pki:
            continue
        payload = int(row.get("payload_bytes", "0"))
        tx_bytes = float_or_none(row.get("l2cap_tx_bytes", ""))
        rx_bytes = float_or_none(row.get("l2cap_rx_bytes", ""))
        if payload <= 0 or tx_bytes is None or rx_bytes is None:
            continue
        chain_id = row.get("pki_chain_id") or row.get("case_id", "unknown")
        grouped[(chain_id, row["direction"], payload)].append(
            max(0.0, tx_bytes + rx_bytes - payload)
        )
    if not grouped:
        return 0

    chains = sorted({key[0] for key in grouped})
    payloads = sorted({key[2] for key in grouped})
    columns = [
        (direction, payload)
        for direction in ("server_to_device", "device_to_server")
        for payload in payloads
    ]
    matrix = np.full((len(chains), len(columns)), np.nan)
    for row_index, chain_id in enumerate(chains):
        for column_index, (direction, payload) in enumerate(columns):
            values = grouped.get((chain_id, direction, payload))
            if values:
                matrix[row_index, column_index] = statistics.mean(values)

    order = sorted(
        range(len(chains)),
        key=lambda index: (np.nanmean(matrix[index]), chains[index]),
        reverse=True,
    )
    chains = [chains[index] for index in order]
    matrix = matrix[order]
    cmap = HEATMAP_CMAP.copy()
    cmap.set_bad("#f1f1f1")
    fig, ax = plt.subplots(
        figsize=(12, max(8, len(chains) * 0.42)), constrained_layout=True,
    )
    image = ax.imshow(np.ma.masked_invalid(matrix), cmap=cmap, aspect="auto")
    ax.set_title(
        f"L2CAP bytes transferred beyond MQTT payload - "
        f"{pki.capitalize()} PKI - {run_id}"
    )
    ax.set_xlabel("Transfer direction and MQTT payload")
    ax.set_ylabel("PKI chain")
    ax.set_xticks(range(len(columns)))
    ax.set_yticks(range(len(chains)))
    ax.set_xticklabels([
        ("S -> D" if direction == "server_to_device" else "D -> S")
        + "\n" + payload_label(payload)
        for direction, payload in columns
    ], fontsize=8)
    ax.set_yticklabels(chains, fontsize=6)
    for row_index in range(len(chains)):
        for column_index in range(len(columns)):
            value = matrix[row_index, column_index]
            if not np.isnan(value):
                ax.text(column_index, row_index, f"{value:.1f}",
                        ha="center", va="center", fontsize=7, color="black")
    fig.colorbar(image, ax=ax).set_label(
        "Mean extra L2CAP bytes: TX + RX - MQTT payload"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return len(chains)


def plot_kem_extra_bytes_heatmap(
    attempts: list[dict[str, str]], output: Path, run_id: str, pki: str,
    direction: str, payload_bytes: int,
) -> int:
    """Compare transfer overhead by KEM and certificate algorithm."""
    values_by_pair: dict[tuple[str, str], list[float]] = defaultdict(list)
    selected_rows = [
        row for row in attempts
        if pki_category(row) == pki
        and row.get("direction") == direction
        and int(row.get("payload_bytes", "0")) == payload_bytes
    ]
    for row in selected_rows:
        tx_bytes = float_or_none(row.get("l2cap_tx_bytes", ""))
        rx_bytes = float_or_none(row.get("l2cap_rx_bytes", ""))
        kem = row.get("kex_group", "")
        signature = pki_signature_label(row)
        if tx_bytes is None or rx_bytes is None or not kem or not signature:
            continue
        values_by_pair[(kem, signature)].append(
            max(0.0, tx_bytes + rx_bytes - payload_bytes)
        )
    if not values_by_pair:
        return 0

    kems, signatures = heatmap_axes_by_descending_mean(values_by_pair)
    matrix = np.full((len(signatures), len(kems)), np.nan)
    for row_index, signature in enumerate(signatures):
        for column_index, kem in enumerate(kems):
            values = values_by_pair.get((kem, signature))
            if values:
                matrix[row_index, column_index] = statistics.mean(values)

    cmap = HEATMAP_CMAP.copy()
    cmap.set_bad("#f1f1f1")
    fig, ax = plt.subplots(
        figsize=(max(10, len(kems) * 0.9), max(7, len(signatures) * 0.55)),
        constrained_layout=True,
    )
    image = ax.imshow(np.ma.masked_invalid(matrix), cmap=cmap, aspect="auto")
    direction_label = (
        "Server to device" if direction == "server_to_device"
        else "Device to server"
    )
    ax.set_title(
        f"Extra L2CAP bytes by KEM and certificate - "
        f"{payload_label(payload_bytes)} - {direction_label} - "
        f"{pki.capitalize()} PKI - {run_id}"
    )
    ax.set_xlabel("KEM / TLS key exchange group")
    ax.set_ylabel("Certificate signature algorithm")
    ax.set_xticks(range(len(kems)))
    ax.set_yticks(range(len(signatures)))
    kem_levels = {
        row.get("kex_group", ""): kem_security_level(row)
        for row in selected_rows
    }
    signature_levels = {
        pki_signature_label(row): signature_security_level(row)
        for row in selected_rows
    }
    ax.set_xticklabels(
        [algorithm_label(kem, kem_levels.get(kem)) for kem in kems],
        rotation=55, ha="right", fontsize=7,
    )
    ax.set_yticklabels(
        [algorithm_label(sig, signature_levels.get(sig)) for sig in signatures],
        fontsize=7,
    )
    for row_index in range(len(signatures)):
        for column_index in range(len(kems)):
            value = matrix[row_index, column_index]
            if not np.isnan(value):
                ax.text(
                    column_index, row_index, f"{value:.1f}",
                    ha="center", va="center", fontsize=11, color="black",
                )
    fig.colorbar(image, ax=ax).set_label(
        "Mean extra L2CAP bytes: TX + RX - MQTT payload"
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return len(values_by_pair)


def generate_heatmaps(
    run_dir: Path, out_dir: Path, extension: str,
) -> tuple[int, int, int]:
    rows = load_transfer_summary(run_dir)
    payloads = sorted({int(row["payload_bytes"]) for row in rows})
    metric_count = 0
    for pki in ("homogeneous", "heterogeneous"):
        for direction in ("server_to_device", "device_to_server"):
            for payload in payloads:
                suffix = (
                    f"{pki}_{direction}_{payload}_bytes.{extension}"
                )
                metric_count += int(plot_transfer_metric_heatmap(
                    rows,
                    "mean_end_to_end_ms",
                    "ci95_end_to_end_ms",
                    out_dir / f"heatmap_transfer_time_{suffix}",
                    run_dir.name, pki, direction, payload,
                    divisor=1.0, decimals=1,
                    colorbar_label="Mean end-to-end transfer time (ms); cells show mean ± 95% CI",
                    annotation_fontsize=12,
                ) > 0)
                metric_count += int(plot_transfer_metric_heatmap(
                    rows,
                    "mean_transfer_energy_uj",
                    "ci95_transfer_energy_uj",
                    out_dir / f"heatmap_transfer_energy_{suffix}",
                    run_dir.name, pki, direction, payload,
                    divisor=1000.0, decimals=3,
                    colorbar_label="Mean transfer energy (mJ); mean ± 95% CI",
                ) > 0)

    attempts = load_transfer_attempts(run_dir)
    overhead_count = 0
    kem_overhead_count = 0
    for pki in ("homogeneous", "heterogeneous"):
        overhead_count += int(plot_extra_bytes_heatmap(
            attempts,
            out_dir / f"heatmap_transfer_extra_bytes_{pki}.{extension}",
            run_dir.name,
            pki,
        ) > 0)
        for direction in ("server_to_device", "device_to_server"):
            for payload in payloads:
                kem_overhead_count += int(plot_kem_extra_bytes_heatmap(
                    attempts,
                    out_dir / (
                        f"heatmap_transfer_extra_bytes_kem_{pki}_{direction}_"
                        f"{payload}_bytes.{extension}"
                    ),
                    run_dir.name, pki, direction, payload,
                ) > 0)
    return metric_count, overhead_count, kem_overhead_count


def generate_table(run_dir: Path, output: Path) -> tuple[int, int]:
    summary = run_dir / "transfer_summary.csv"
    if not summary.exists():
        raise FileNotFoundError(f"Transfer summary not found: {summary}")
    with summary.open(newline="") as stream:
        rows = list(csv.DictReader(stream))

    payloads = sorted({int(row["payload_bytes"]) for row in rows})
    cases = sorted({row["case_id"] for row in rows})
    directions = ("server_to_device", "device_to_server")
    direction_labels = {
        "server_to_device": r"Server $\rightarrow$ device",
        "device_to_server": r"Device $\rightarrow$ server",
    }
    indexed = {
        (row["case_id"], row["direction"], int(row["payload_bytes"])): row
        for row in rows
    }

    columns = "@{}p{0.48\\textwidth}l" + "r" * len(payloads) + "@{}"
    lines = [
        r"{\scriptsize",
        r"\setlength{\tabcolsep}{3pt}",
        rf"\begin{{longtable}}{{{columns}}}",
        r"\hline",
        "Configuration & Direction & "
        + " & ".join(latex_escape(payload_label(value)) for value in payloads)
        + r" \\",
        r"\hline",
        r"\endfirsthead",
        r"\hline",
        "Configuration & Direction & "
        + " & ".join(latex_escape(payload_label(value)) for value in payloads)
        + r" \\",
        r"\hline",
        r"\endhead",
        r"\hline",
        rf"\multicolumn{{{2 + len(payloads)}}}{{r}}{{Continued on next page}} \\",
        r"\endfoot",
        r"\hline",
        r"\endlastfoot",
    ]
    missing = 0
    for case_id in cases:
        for direction_index, direction in enumerate(directions):
            cells = [energy_cell(indexed.get((case_id, direction, size))) for size in payloads]
            missing += sum(cell == "--" for cell in cells)
            configuration = latex_escape(case_id) if direction_index == 0 else ""
            lines.append(
                f"{configuration} & {direction_labels[direction]} & "
                + " & ".join(cells)
                + r" \\"
            )
    lines.extend((r"\end{longtable}", r"}"))

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(lines) + "\n", encoding="ascii")
    return len(cases), missing


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", help="transfer benchmark run directory or run id")
    parser.add_argument("--output", type=Path, help="output .tex path")
    parser.add_argument(
        "--heatmap", action="store_true",
        help="also generate time, energy, and transferred-overhead heatmaps",
    )
    parser.add_argument(
        "--scatter", action="store_true",
        help="also generate the transfer time versus energy scatter plot",
    )
    parser.add_argument(
        "--generate-png", action="store_true",
        help="generate PNG heatmaps instead of the default PDF",
    )
    args = parser.parse_args()

    run_dir = resolve_run_dir(args.run_dir)
    output = args.output or (
        ROOT / "graphic" / "out" / run_dir.name / "transfer_energy_table.tex"
    )
    cases, missing = generate_table(run_dir, output.resolve())
    print(f"cases={cases}")
    print(f"missing_energy_cells={missing}")
    print(f"output={output.resolve()}")
    if args.heatmap:
        extension = "png" if args.generate_png else "pdf"
        metric_count, overhead_count, kem_overhead_count = generate_heatmaps(
            run_dir, output.resolve().parent, extension,
        )
        print(f"transfer_metric_heatmaps={metric_count}")
        print(f"transfer_overhead_heatmaps={overhead_count}")
        print(f"transfer_kem_overhead_heatmaps={kem_overhead_count}")
        print(f"heatmap_format={extension}")
    if args.scatter:
        extension = "png" if args.generate_png else "pdf"
        points = plot_transfer_time_energy_scatter(
            load_transfer_summary(run_dir),
            output.resolve().parent / f"scatter_transfer_time_energy.{extension}",
            run_dir.name,
        )
        print(f"transfer_scatter_points={points}")
        print(
            "transfer_scatter="
            f"{output.resolve().parent / f'scatter_transfer_time_energy.{extension}'}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
