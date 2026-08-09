#!/usr/bin/env python3
"""Plot certificate benchmark summary metrics from a result directory."""

from __future__ import annotations

import argparse
import csv
from pathlib import Path

try:
    import matplotlib.pyplot as plt
    import numpy as np
    from matplotlib.colors import LogNorm
    from matplotlib.font_manager import FontProperties
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


def format_duration_ms(value: float) -> str:
    if value >= 60000.0:
        return f"{value / 60000.0:.1f} min"
    if value >= 1000.0:
        return f"{value / 1000.0:.1f} s"
    return f"{value:.0f} ms"


def format_density(value: float) -> str:
    if value >= 1000.0:
        return f"{value / 1000.0:.1f}k"
    if value >= 10.0:
        return f"{value:.0f}"
    return f"{value:.2f}"


def floor_decimals(value: float, decimals: int) -> float:
    factor = 10.0 ** decimals
    return int(value * factor) / factor


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
    level = row.get("sig_nist_level", "")
    level_suffix = f" (L{level})" if level else ""
    if component == "client_identity":
        return "Board key + CSR"
    if component == "client_certificate":
        return f"Board: {signature}{level_suffix}"
    return f"{signature}{level_suffix}"


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

PHASE_WALL_FIELDS = [
    ("mean_keygen_wall_ms", "Keygen", "#2563eb"),
    ("mean_make_cert_wall_ms", "Make cert", "#64748b"),
    ("mean_sign_cert_wall_ms", "Sign cert", "#dc2626"),
    ("mean_parse_cert_wall_ms", "Parse verify", "#0f766e"),
    ("mean_key_export_wall_ms", "Key export", "#9333ea"),
]

PHASE_LSU_FIELDS = [
    ("mean_keygen_lsu_cycles", "Keygen", "#2563eb"),
    ("mean_make_cert_lsu_cycles", "Make cert", "#64748b"),
    ("mean_sign_cert_lsu_cycles", "Sign cert", "#dc2626"),
    ("mean_parse_cert_lsu_cycles", "Parse verify", "#0f766e"),
    ("mean_key_export_lsu_cycles", "Key export", "#9333ea"),
]

PHASE_CPI_FIELDS = [
    ("mean_keygen_cpi_cycles", "Keygen", "#2563eb"),
    ("mean_make_cert_cpi_cycles", "Make cert", "#64748b"),
    ("mean_sign_cert_cpi_cycles", "Sign cert", "#dc2626"),
    ("mean_parse_cert_cpi_cycles", "Parse verify", "#0f766e"),
    ("mean_key_export_cpi_cycles", "Key export", "#9333ea"),
]

PHASE_CORE_FIELDS = [
    ("mean_keygen_core_cycles", "Keygen", "#2563eb"),
    ("mean_make_cert_core_cycles", "Make cert", "#64748b"),
    ("mean_sign_cert_core_cycles", "Sign cert", "#dc2626"),
    ("mean_parse_cert_core_cycles", "Parse verify", "#0f766e"),
    ("mean_key_export_core_cycles", "Key export", "#9333ea"),
]

PHASE_EXC_FIELDS = [
    ("mean_keygen_exc_cycles", "Keygen", "#2563eb"),
    ("mean_make_cert_exc_cycles", "Make cert", "#64748b"),
    ("mean_sign_cert_exc_cycles", "Sign cert", "#dc2626"),
    ("mean_parse_cert_exc_cycles", "Parse verify", "#0f766e"),
    ("mean_key_export_exc_cycles", "Key export", "#9333ea"),
]

PHASE_SLEEP_FIELDS = [
    ("mean_keygen_sleep_cycles", "Keygen", "#2563eb"),
    ("mean_make_cert_sleep_cycles", "Make cert", "#64748b"),
    ("mean_sign_cert_sleep_cycles", "Sign cert", "#dc2626"),
    ("mean_parse_cert_sleep_cycles", "Parse verify", "#0f766e"),
    ("mean_key_export_sleep_cycles", "Key export", "#9333ea"),
]

PHASE_FOLD_FIELDS = [
    ("mean_keygen_fold_events", "Keygen", "#2563eb"),
    ("mean_make_cert_fold_events", "Make cert", "#64748b"),
    ("mean_sign_cert_fold_events", "Sign cert", "#dc2626"),
    ("mean_parse_cert_fold_events", "Parse verify", "#0f766e"),
    ("mean_key_export_fold_events", "Key export", "#9333ea"),
]

PHASE_HEAP_FIELDS = [
    ("max_keygen_heap_peak_bytes", "Keygen", "#2563eb"),
    ("max_make_cert_heap_peak_bytes", "Make cert", "#64748b"),
    ("max_sign_cert_heap_peak_bytes", "Sign cert", "#dc2626"),
    ("max_parse_cert_heap_peak_bytes", "Parse verify", "#0f766e"),
    ("max_key_export_heap_peak_bytes", "Key export", "#9333ea"),
]

PHASE_MAIN_THREAD_FIELDS = [
    ("mean_keygen_thread_main_cpu_percent", "Keygen", "#2563eb"),
    ("mean_make_cert_thread_main_cpu_percent", "Make cert", "#64748b"),
    ("mean_sign_cert_thread_main_cpu_percent", "Sign cert", "#dc2626"),
    ("mean_parse_cert_thread_main_cpu_percent", "Parse verify", "#0f766e"),
    ("mean_key_export_thread_main_cpu_percent", "Key export", "#9333ea"),
]

SERVER_RESOURCE_PANELS = [
    (
        "Peak RSS",
        [
            ("max_rss_kb", "RSS", "#2563eb"),
        ],
        "Peak resident memory (KB)",
    ),
    (
        "Context switches",
        [
            ("mean_voluntary_context_switches", "Voluntary", "#2563eb"),
            ("mean_involuntary_context_switches", "Involuntary", "#dc2626"),
        ],
        "Mean context switches",
    ),
    (
        "Page faults",
        [
            ("mean_minor_page_faults", "Minor", "#0f766e"),
            ("mean_major_page_faults", "Major", "#f97316"),
        ],
        "Mean page faults",
    ),
    (
        "Block I/O ops",
        [
            ("mean_block_input_ops", "Input", "#64748b"),
            ("mean_block_output_ops", "Output", "#9333ea"),
        ],
        "Mean block I/O ops",
    ),
]


def signature_sort_key(name: str) -> tuple[int, int, int, str]:
    upper = name.upper()
    if upper.startswith("ECDSA-P-"):
        return (0, int(upper.rsplit("-", 1)[1]), 0, upper)
    if upper.startswith("RSA-PSS-"):
        return (1, int(upper.rsplit("-", 1)[1]), 0, upper)
    if upper.startswith("ML-DSA-"):
        return (2, int(upper.rsplit("-", 1)[1]), 0, upper)
    if upper.startswith("SLH-DSA-SHAKE-"):
        family = upper.rsplit("-", 1)[1]
        level = int("".join(ch for ch in family if ch.isdigit()) or "0")
        variant = 0 if family.endswith("S") else 1
        return (3, level, variant, upper)
    if upper.startswith("LMS-"):
        return (4, 0, 0, upper)
    if upper.startswith("XMSS-"):
        return (5, 0, 0, upper)
    return (99, 0, 0, upper)


def family_color(row: dict[str, str]) -> str:
    return "#0f766e" if row.get("sig_family") == "pqc" else "#64748b"


def add_family_legend(ax, *, loc: str = "lower right") -> None:
    legend_handles = [
        plt.Rectangle((0, 0), 1, 1, color="#64748b", label="Classic"),
        plt.Rectangle((0, 0), 1, 1, color="#0f766e", label="PQC"),
    ]
    ax.legend(handles=legend_handles, loc=loc, fontsize=8)


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
            row.get("component") != "client_identity",
            row.get("component") not in {"client_identity", "client_certificate"},
            signature_sort_key(row.get("cert_sig_alg", "")),
            row.get("builder", ""),
            row_label(row).lower(),
        ),
    )


def annotate_bars(
    ax,
    bars,
    values: list[float],
    *,
    suffix: str = "",
    decimals: int = 0,
) -> None:
    for bar, value in zip(bars, values):
        if value <= 0:
            continue
        ax.annotate(
            f"{value:,.{decimals}f}{suffix}",
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


def annotate_scatter_nonoverlap(
    ax,
    xs: list[float],
    ys: list[float],
    labels: list[str],
    sizes: list[float] | None = None,
) -> None:
    if not xs:
        return
    ax.figure.canvas.draw()
    renderer = ax.figure.canvas.get_renderer()
    font_size = 7
    font_properties = FontProperties(size=font_size)
    x_mid = float(np.median(xs))
    entries = []
    if sizes is None:
        sizes = [30.0] * len(xs)
    for x, y, label, size in zip(xs, ys, labels, sizes):
        x_display, y_display = ax.transData.transform((x, y))
        _width, height, _descent = renderer.get_text_width_height_descent(
            label,
            font_properties,
            ismath=False,
        )
        radius = (float(size) / np.pi) ** 0.5 * ax.figure.dpi / 72.0
        entries.append({
            "x": x,
            "y": y,
            "label": label,
            "x_display": x_display,
            "y_display": y_display,
            "height": height + 7.0,
            "radius": radius,
            "right": x <= x_mid,
        })
    entries.sort(key=lambda item: item["y_display"])

    lower = ax.bbox.y0 + 10.0
    upper = ax.bbox.y1 - 10.0
    adjusted = [
        min(
            max(item["y_display"], lower + item["height"] / 2.0),
            upper - item["height"] / 2.0,
        )
        for item in entries
    ]
    for index in range(1, len(adjusted)):
        min_gap = (
            entries[index - 1]["height"] / 2.0 +
            entries[index]["height"] / 2.0 +
            5.0
        )
        adjusted[index] = max(adjusted[index], adjusted[index - 1] + min_gap)
    if adjusted and adjusted[-1] > upper:
        overflow = adjusted[-1] + entries[-1]["height"] / 2.0 - upper
        adjusted = [value - overflow for value in adjusted]
    for index in range(len(adjusted) - 2, -1, -1):
        min_gap = (
            entries[index]["height"] / 2.0 +
            entries[index + 1]["height"] / 2.0 +
            5.0
        )
        adjusted[index] = min(adjusted[index], adjusted[index + 1] - min_gap)
    if adjusted and adjusted[0] < lower:
        underflow = lower - (adjusted[0] - entries[0]["height"] / 2.0)
        adjusted = [value + underflow for value in adjusted]

    inverse = ax.transData.inverted()
    for item, label_y_display in zip(entries, adjusted):
        x_offset = item["radius"] + 10.0
        if not item["right"]:
            x_offset = -x_offset
        label_x, label_y = inverse.transform(
            (item["x_display"] + x_offset, label_y_display)
        )
        ax.annotate(
            item["label"],
            (item["x"], item["y"]),
            xytext=(label_x, label_y),
            textcoords="data",
            fontsize=font_size,
            ha="left" if item["right"] else "right",
            va="center",
            annotation_clip=False,
            arrowprops={
                "arrowstyle": "-",
                "color": "#64748b",
                "linewidth": 0.45,
                "shrinkA": 0,
                "shrinkB": 2,
            },
            bbox={
                "boxstyle": "round,pad=0.16",
                "facecolor": "#ffffff",
                "edgecolor": "none",
                "alpha": 0.82,
            },
        )


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
        plt.Rectangle((0, 0), 1, 1, color="#2563eb", label="Board/wolfSSL"),
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
    positions = np.arange(len(rows), dtype=float)
    height = max(7.0, len(rows) * 0.68)
    fig, ax = plt.subplots(figsize=(13, height), constrained_layout=True)
    fig.suptitle(f"Certificate CPU phase breakdown - {run_id}", fontsize=15)

    bar_height = min(0.13, 0.72 / len(PHASE_FIELDS))
    offsets = (
        np.arange(len(PHASE_FIELDS), dtype=float) - (len(PHASE_FIELDS) - 1) / 2.0
    ) * bar_height
    all_values: list[float] = []
    for field, label, color in PHASE_FIELDS:
        idx = [item[0] for item in PHASE_FIELDS].index(field)
        values = np.array(numeric(rows, field))
        positive = values > 0
        all_values.extend(float(value) for value in values if value > 0)
        ax.barh(
            positions[positive] + offsets[idx], values[positive],
            height=bar_height, label=label, color=color,
            edgecolor="#111827", linewidth=0.25
        )

    totals = [phase_total(row) for row in rows]
    ax.set_xlabel("Mean phase CPU time (ms, log scale)")
    ax.set_xscale("log")
    ax.set_yticks(positions)
    ax.set_yticklabels(labels, fontsize=9)
    ax.grid(axis="x", linestyle=":", alpha=0.35)
    ax.legend(loc="lower right", fontsize=8)
    ax.invert_yaxis()
    pad_x_axis(ax, all_values or totals, log_scale=True)

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


def plot_phase_cpu_vs_cpi_share(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    fields = [field for field, _label, _color in PHASE_FIELDS] + [
        field for field, _label, _color in PHASE_CPI_FIELDS
    ] + [
        field for field, _label, _color in PHASE_LSU_FIELDS
    ]
    rows = sort_rows(positive_rows(rows, fields))
    if not rows:
        return False

    labels = [row_label(row) for row in rows]
    centers = np.arange(len(rows), dtype=float) * 2.8
    cpu_positions = centers - 0.46
    cpi_positions = centers
    lsu_positions = centers + 0.46
    height = max(8.0, len(rows) * 0.92)
    fig, ax = plt.subplots(figsize=(13, height), constrained_layout=True)
    fig.suptitle(
        f"Certificate phase CPU vs CPICNT vs LSUCNT share - {run_id}",
        fontsize=15,
    )

    cpu_totals = np.array([
        sum(float_or_none(row.get(field)) or 0.0 for field, _label, _color in PHASE_FIELDS)
        for row in rows
    ])
    cpi_totals = np.array([
        sum(float_or_none(row.get(field)) or 0.0 for field, _label, _color in PHASE_CPI_FIELDS)
        for row in rows
    ])
    lsu_totals = np.array([
        sum(float_or_none(row.get(field)) or 0.0 for field, _label, _color in PHASE_LSU_FIELDS)
        for row in rows
    ])
    cpu_left = np.zeros(len(rows))
    cpi_left = np.zeros(len(rows))
    lsu_left = np.zeros(len(rows))
    for (
        (cpu_field, label, color),
        (cpi_field, _cpi_label, _cpi_color),
        (lsu_field, _lsu_label, _lsu_color),
    ) in zip(
        PHASE_FIELDS, PHASE_CPI_FIELDS, PHASE_LSU_FIELDS
    ):
        cpu_values = np.array(numeric(rows, cpu_field))
        cpi_values = np.array(numeric(rows, cpi_field))
        lsu_values = np.array(numeric(rows, lsu_field))
        cpu_shares = np.divide(
            cpu_values * 100.0,
            cpu_totals,
            out=np.zeros_like(cpu_values),
            where=cpu_totals > 0,
        )
        cpi_shares = np.divide(
            cpi_values * 100.0,
            cpi_totals,
            out=np.zeros_like(cpi_values),
            where=cpi_totals > 0,
        )
        lsu_shares = np.divide(
            lsu_values * 100.0,
            lsu_totals,
            out=np.zeros_like(lsu_values),
            where=lsu_totals > 0,
        )
        ax.barh(
            cpu_positions, cpu_shares, left=cpu_left, label=label,
            color=color, edgecolor="#111827", linewidth=0.25
        )
        ax.barh(
            cpi_positions, cpi_shares, left=cpi_left,
            color=color, edgecolor="#111827", linewidth=0.25, alpha=0.72
        )
        ax.barh(
            lsu_positions, lsu_shares, left=lsu_left,
            color=color, edgecolor="#111827", linewidth=0.25, alpha=0.50
        )
        cpu_left += cpu_shares
        cpi_left += cpi_shares
        lsu_left += lsu_shares

    for center in centers:
        ax.text(101.0, center - 0.46, "CPU", va="center", fontsize=7, color="#374151")
        ax.text(101.0, center, "CPI", va="center", fontsize=7, color="#374151")
        ax.text(101.0, center + 0.46, "LSU", va="center", fontsize=7, color="#374151")

    ax.set_xlabel("Share within measured phases (%)")
    ax.set_xlim(0, 108)
    ax.set_yticks(centers)
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
    title_suffix: str = "",
    color_func=row_color,
    annotate_scatter: bool = True,
) -> bool:
    rows = sort_rows([
        row for row in rows
        if cpu_ms(row) > 0 and output_size_bytes(row) > 0
    ])
    if not rows:
        return False

    labels = [row_label(row) for row in rows]
    colors = [color_func(row) for row in rows]
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
    title = "Certificate CPU cost normalized by output"
    if title_suffix:
        title = f"{title} ({title_suffix})"
    fig.suptitle(f"{title} - {run_id}", fontsize=15)

    bars = axes[0].barh(
        positions, cpu_per_kb, color=colors, edgecolor="#111827", linewidth=0.35
    )
    axes[0].set_xlabel("CPU ms per output KB")
    axes[0].set_yticks(positions)
    axes[0].set_yticklabels(labels, fontsize=9)
    axes[0].grid(axis="x", linestyle=":", alpha=0.35)
    axes[0].set_xscale("log")
    pad_x_axis(axes[0], cpu_per_kb, log_scale=True)
    annotate_bars(axes[0], bars, cpu_per_kb, decimals=2)

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
    axes[1].set_xlabel("Generated output (KB)")
    axes[1].set_ylabel("CPU time (ms)")
    axes[1].set_xscale("log")
    axes[1].set_yscale("log")
    axes[1].grid(linestyle=":", alpha=0.35)
    if annotate_scatter:
        annotate_scatter_nonoverlap(
            axes[1], output_kb, [cpu_ms(row) for row in rows], labels, scatter_sizes
        )

    axes[0].text(
        0.02, 0.02,
        "Right plot bubble size follows peak memory where available.",
        transform=axes[0].transAxes,
        fontsize=8,
        color="#374151",
    )
    axes[0].invert_yaxis()
    if color_func is family_color:
        add_family_legend(axes[0])

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return True


def plot_board_cpu_efficiency(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    board_rows = [
        row for row in rows
        if row.get("component") in {"client_certificate", "client_identity"}
        or row.get("builder") == "wolfssl_board"
    ]
    return plot_cpu_efficiency(
        board_rows, output, run_id, "board", color_func=family_color
    )


def plot_server_cpu_efficiency(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    server_rows = [
        row for row in rows
        if row.get("component") == "server_chain"
        or row.get("owner") == "server"
    ]
    return plot_cpu_efficiency(
        server_rows, output, run_id, "server", annotate_scatter=True
    )


def plot_wall_cpu_gap(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    rows = sort_rows([
        row for row in rows
        if (float_or_none(row.get("mean_wall_ms")) or 0.0) > 0 and cpu_ms(row) > 0
    ])
    if not rows:
        return False

    labels = [row_label(row) for row in rows]
    colors = [row_color(row) for row in rows]
    positions = np.arange(len(rows))
    wall = numeric(rows, "mean_wall_ms")
    cpu = [cpu_ms(row) for row in rows]
    raw_cpu_share = [
        (cpu_value / wall_value) * 100.0 if wall_value > 0 else 0.0
        for cpu_value, wall_value in zip(cpu, wall)
    ]
    cpu_share = [
        min(100.0, max(0.0, floor_decimals(value, 3)))
        for value in raw_cpu_share
    ]
    wall_gap_us = [
        max(wall_value - cpu_value, 0.0) * 1000.0
        for cpu_value, wall_value in zip(cpu, wall)
    ]

    height = max(8.0, len(rows) * 0.46)
    fig, axes = plt.subplots(
        1, 2,
        figsize=(16, height),
        sharey=True,
        constrained_layout=True,
    )
    fig.suptitle(f"Certificate wall time vs measured CPU time - {run_id}", fontsize=15)

    share_bars = axes[0].barh(
        positions, cpu_share, color=colors, edgecolor="#111827", linewidth=0.35
    )
    axes[0].axvline(100.0, color="#111827", linestyle=":", linewidth=0.9)
    axes[0].set_xlabel("CPU time / wall time (%)")
    axes[0].set_xlim(0, max(105.0, max(cpu_share) * 1.12 if cpu_share else 105.0))
    axes[0].set_yticks(positions)
    axes[0].set_yticklabels(labels, fontsize=9)
    axes[0].grid(axis="x", linestyle=":", alpha=0.35)
    annotate_bars(axes[0], share_bars, cpu_share, suffix="%", decimals=3)

    gap_bars = axes[1].barh(
        positions, wall_gap_us, color="#f97316", edgecolor="#111827", linewidth=0.35
    )
    axes[1].set_xlabel("Wall time not explained by measured CPU (us)")
    axes[1].grid(axis="x", linestyle=":", alpha=0.35)
    positive_gap = [value for value in wall_gap_us if value > 0]
    if positive_gap:
        axes[1].set_xscale("log")
        pad_x_axis(axes[1], positive_gap, log_scale=True)
        annotate_bars(axes[1], gap_bars, wall_gap_us, suffix=" us")
    else:
        axes[1].set_xlim(0, 1)

    legend_handles = [
        plt.Rectangle((0, 0), 1, 1, color="#2563eb", label="Board/wolfSSL"),
        plt.Rectangle((0, 0), 1, 1, color="#64748b", label="Classic/OpenSSL"),
        plt.Rectangle((0, 0), 1, 1, color="#0f766e", label="PQC/OpenSSL"),
        plt.Rectangle((0, 0), 1, 1, color="#7c3aed", label="HBS/wolfSSL"),
        plt.Rectangle((0, 0), 1, 1, color="#f97316", label="Wall minus CPU"),
    ]
    axes[0].legend(handles=legend_handles, loc="lower right", fontsize=8)

    for ax in axes:
        ax.invert_yaxis()

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return True


def plot_resource_pressure(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    original_rows = rows
    ram_fields = ["firmware_static_ram_used_bytes", "firmware_ram_capacity_bytes"]
    fields = ram_fields
    rows = sort_rows(positive_rows(rows, fields))
    use_firmware_ram = bool(rows)
    if not rows:
        fields = ["max_client_heap_peak_bytes", "max_thread_stack_peak_percent"]
        rows = sort_rows(positive_rows(original_rows, fields))
    if not rows:
        return False

    labels = [row_label(row) for row in rows]
    colors = [family_color(row) for row in rows]
    positions = np.arange(len(rows))

    height = max(7.0, len(rows) * 0.46)
    fig, axes = plt.subplots(
        1, 2,
        figsize=(15, height),
        sharey=True,
        constrained_layout=True,
    )
    title = "Board certificate firmware RAM pressure" if use_firmware_ram else (
        "Board certificate resource pressure"
    )
    fig.suptitle(f"{title} - {run_id}", fontsize=15)

    if use_firmware_ram:
        ram_kb = [
            (float_or_none(row.get("firmware_static_ram_used_bytes")) or 0.0) / 1024.0
            for row in rows
        ]
        ram_pct = [
            (
                (float_or_none(row.get("firmware_static_ram_used_bytes")) or 0.0) *
                100.0 /
                (float_or_none(row.get("firmware_ram_capacity_bytes")) or 1.0)
            )
            for row in rows
        ]
        left_bars = axes[0].barh(
            positions, ram_kb, color=colors, edgecolor="#111827", linewidth=0.35
        )
        axes[0].set_xlabel("Firmware RAM used (KB)")
        pad_x_axis(axes[0], ram_kb, log_scale=False)
        annotate_bars(axes[0], left_bars, ram_kb, suffix=" KB")

        right_bars = axes[1].barh(
            positions, ram_pct, color=colors, edgecolor="#111827", linewidth=0.35
        )
        axes[1].set_xlabel("Firmware RAM used / nRF SRAM (%)")
        axes[1].set_xlim(0, max(100.0, max(ram_pct) * 1.12 if ram_pct else 100.0))
        annotate_bars(axes[1], right_bars, ram_pct, suffix="%")
    else:
        heap_kb = [
            (float_or_none(row.get("max_client_heap_peak_bytes")) or 0.0) / 1024.0
            for row in rows
        ]
        stack_pct = numeric(rows, "max_thread_stack_peak_percent")
        phase_verify = [row.get("phase_cpu_verify", "") for row in rows]
        heap_bars = axes[0].barh(
            positions, heap_kb, color=colors, edgecolor="#111827", linewidth=0.35
        )
        axes[0].set_xlabel("Peak wolfSSL heap (KB)")
        pad_x_axis(axes[0], heap_kb, log_scale=False)
        annotate_bars(axes[0], heap_bars, heap_kb, suffix=" KB")

        stack_hatches = ["//" if verify == "fail" else "" for verify in phase_verify]
        stack_bars = axes[1].barh(
            positions, stack_pct, color=colors, edgecolor="#111827", linewidth=0.35
        )
        for bar, hatch in zip(stack_bars, stack_hatches):
            bar.set_hatch(hatch)
        axes[1].set_xlabel("Peak thread stack usage (%)")
        axes[1].set_xlim(0, max(100.0, max(stack_pct) * 1.12 if stack_pct else 100.0))
        annotate_bars(axes[1], stack_bars, stack_pct, suffix="%")

    axes[0].set_yticks(positions)
    axes[0].set_yticklabels(labels, fontsize=9)
    for ax in axes:
        ax.grid(axis="x", linestyle=":", alpha=0.35)
    add_family_legend(axes[0])

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


def plot_total_cpi(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    rows = sort_rows(positive_rows(rows, ["mean_phase_cpi_total_cycles"]))
    if not rows:
        return False

    labels = [row_label(row) for row in rows]
    colors = [family_color(row) for row in rows]
    positions = np.arange(len(rows))
    values = numeric(rows, "mean_phase_cpi_total_cycles")
    height = max(7.0, len(rows) * 0.46)
    fig, ax = plt.subplots(figsize=(12, height), constrained_layout=True)
    fig.suptitle(f"Board certgen total CPICNT - {run_id}", fontsize=15)

    bars = ax.barh(
        positions, values, color=colors, edgecolor="#111827", linewidth=0.35
    )
    ax.set_xlabel("Total CPICNT delta across measured phases (log scale)")
    ax.set_xscale("log")
    ax.set_yticks(positions)
    ax.set_yticklabels(labels, fontsize=9)
    ax.grid(axis="x", linestyle=":", alpha=0.35)
    pad_x_axis(ax, values, log_scale=True)
    annotate_bars(ax, bars, values)
    add_family_legend(ax)
    ax.invert_yaxis()

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return True


def plot_stacked_absolute(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
    fields: list[tuple[str, str, str]],
    title: str,
    xlabel: str,
    *,
    divide_by: float = 1.0,
    log_scale: bool = False,
    annotate_cpu_ms: bool = False,
    legend_loc: str = "lower right",
    legend_bbox_to_anchor: tuple[float, float] | None = None,
    legend_ncol: int = 1,
) -> bool:
    rows = sort_rows(positive_rows(rows, [field for field, _label, _color in fields]))
    if not rows:
        return False

    labels = [row_label(row) for row in rows]
    positions = np.arange(len(rows))
    height = max(7.0, len(rows) * 0.46)
    fig, ax = plt.subplots(figsize=(12, height), constrained_layout=True)
    fig.suptitle(f"{title} - {run_id}", fontsize=15)

    left = np.zeros(len(rows))
    for field, label, color in fields:
        values = np.array(numeric(rows, field)) / divide_by
        ax.barh(
            positions, values, left=left, label=label, color=color,
            edgecolor="#111827", linewidth=0.25
        )
        left += values

    ax.set_xlabel(xlabel)
    ax.set_yticks(positions)
    ax.set_yticklabels(labels, fontsize=9)
    ax.grid(axis="x", linestyle=":", alpha=0.35)
    if log_scale:
        ax.set_xscale("log")
    pad_x_axis(ax, list(left), log_scale=log_scale)
    if annotate_cpu_ms:
        for y, total, row in zip(positions, left, rows):
            if total <= 0:
                continue
            ax.annotate(
                f"CPU {phase_total(row):,.0f} ms",
                xy=(total, y),
                xytext=(5, 0),
                textcoords="offset points",
                ha="left",
                va="center",
                fontsize=8,
            )
    ax.legend(
        loc=legend_loc,
        bbox_to_anchor=legend_bbox_to_anchor,
        ncol=legend_ncol,
        fontsize=8,
    )
    ax.invert_yaxis()

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return True


def plot_phase_wall_heatmap(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
    *,
    fields: list[tuple[str, str, str]] = PHASE_WALL_FIELDS,
    cpu_fields: list[tuple[str, str, str]] = PHASE_FIELDS,
    title: str = "Board certgen phase wall time heatmap",
    xlabel: str = "Certificate generation phase",
    total_cpu_func=phase_total,
) -> bool:
    rows = sort_rows(positive_rows(rows, [field for field, _label, _color in fields]))
    if not rows:
        return False

    labels = [row_label(row) for row in rows]
    phase_labels = [label for _field, label, _color in fields]
    matrix = np.array([
        [
            float_or_none(row.get(field)) or 0.0
            for field, _label, _color in fields
        ]
        for row in rows
    ], dtype=float)
    cpu_matrix = np.array([
        [
            float_or_none(row.get(field)) or 0.0
            for field, _label, _color in cpu_fields
        ]
        for row in rows
    ], dtype=float)
    sub_ms = (matrix <= 0) & (cpu_matrix > 0)
    display = np.where(matrix > 0, matrix, np.where(sub_ms, 1.0, np.nan))
    positive = display[~np.isnan(display)]
    if len(positive) == 0:
        return False
    cmap = plt.get_cmap("YlGnBu").copy()
    cmap.set_bad("#f8fafc")

    height = max(7.0, len(rows) * 0.58)
    fig, ax = plt.subplots(figsize=(13, height), constrained_layout=True)
    fig.suptitle(f"{title} - {run_id}", fontsize=15)

    vmin = max(1.0, float(positive.min()))
    vmax = float(positive.max())
    text_flip = (vmin * vmax) ** 0.5
    image = ax.imshow(
        display,
        aspect="auto",
        cmap=cmap,
        norm=LogNorm(vmin=vmin, vmax=vmax),
    )

    ax.set_xticks(np.arange(len(fields)))
    ax.set_xticklabels(phase_labels, fontsize=9)
    ax.set_yticks(np.arange(len(rows)))
    ax.set_yticklabels(labels, fontsize=9)
    ax.set_xlim(-0.5, len(fields) + 1.35)
    ax.set_xlabel(xlabel)
    ax.set_ylabel("Certificate")
    ax.grid(which="minor", color="#ffffff", linewidth=1.2)
    ax.set_xticks(np.arange(-0.5, len(fields), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(rows), 1), minor=True)
    ax.tick_params(which="minor", bottom=False, left=False)

    for y, row in enumerate(rows):
        for x, value in enumerate(matrix[y]):
            label = format_duration_ms(value) if value > 0 else "<1 ms"
            display_value = display[y, x]
            if np.isnan(display_value):
                continue
            ax.text(
                x, y, label,
                ha="center",
                va="center",
                fontsize=8,
                color="#f8fafc" if display_value >= text_flip else "#111827",
            )
        ax.text(
            len(fields) + 0.08,
            y,
            f"CPU {format_duration_ms(total_cpu_func(row))}",
            ha="left",
            va="center",
            fontsize=8,
            color="#111827",
        )
    ax.text(
        len(fields) + 0.08,
        -0.72,
        "Total CPU",
        ha="left",
        va="center",
        fontsize=9,
        color="#374151",
    )

    colorbar = fig.colorbar(image, ax=ax, fraction=0.028, pad=0.02)
    colorbar.set_label("Wall time per phase (ms, log color scale)")

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return True


def plot_server_phase_wall_ms(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    rows = sort_rows([
        row for row in rows
        if (
            row.get("component") == "server_chain"
        or row.get("owner") == "server"
        ) and (float_or_none(row.get("mean_wall_ms")) or 0.0) > 0
    ])
    if not rows:
        return False

    labels = [row_label(row) for row in rows]
    values = numeric(rows, "mean_wall_ms")
    colors = [row_color(row) for row in rows]
    positions = np.arange(len(rows))
    height = max(7.0, len(rows) * 0.46)
    fig, ax = plt.subplots(figsize=(12, height), constrained_layout=True)
    fig.suptitle(f"Server certificate chain wall time - {run_id}", fontsize=15)

    bars = ax.barh(
        positions, values, color=colors, edgecolor="#111827", linewidth=0.35
    )
    ax.set_xlabel("Mean wall time (ms, log scale)")
    ax.set_xscale("log")
    ax.set_yticks(positions)
    ax.set_yticklabels(labels, fontsize=9)
    ax.grid(axis="x", linestyle=":", alpha=0.35)
    pad_x_axis(ax, values, log_scale=True)
    annotate_bars(ax, bars, values, suffix=" ms")
    ax.invert_yaxis()

    legend_handles = [
        plt.Rectangle((0, 0), 1, 1, color="#64748b", label="Classic/OpenSSL"),
        plt.Rectangle((0, 0), 1, 1, color="#0f766e", label="PQC/OpenSSL"),
        plt.Rectangle((0, 0), 1, 1, color="#7c3aed", label="HBS/wolfSSL"),
    ]
    ax.legend(handles=legend_handles, loc="upper right", fontsize=8)

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return True


def plot_phase_density_heatmap(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
    numerator_fields: list[tuple[str, str, str]],
    denominator_fields: list[tuple[str, str, str]],
    title: str,
    colorbar_label: str,
    *,
    log_scale: bool = True,
    scale: float = 1.0,
) -> bool:
    fields = [
        field for field, _label, _color in numerator_fields + denominator_fields
    ]
    rows = sort_rows(positive_rows(rows, fields))
    if not rows:
        return False

    labels = [row_label(row) for row in rows]
    phase_labels = [label for _field, label, _color in numerator_fields]
    matrix = []
    for row in rows:
        matrix_row = []
        for (num_field, _label, _color), (den_field, _den_label, _den_color) in zip(
            numerator_fields, denominator_fields
        ):
            numerator = float_or_none(row.get(num_field)) or 0.0
            denominator = float_or_none(row.get(den_field)) or 0.0
            matrix_row.append(
                (numerator / denominator) * scale
                if numerator > 0.0 and denominator > 0.0
                else np.nan
            )
        matrix.append(matrix_row)
    matrix = np.array(matrix, dtype=float)
    positive = matrix[~np.isnan(matrix)]
    if len(positive) == 0:
        return False

    cmap = plt.get_cmap("YlOrRd").copy()
    cmap.set_bad("#f8fafc")
    vmin = float(positive.min())
    vmax = float(positive.max())
    if vmin == vmax:
        vmax = vmin * 1.01
    norm = LogNorm(vmin=max(vmin, 1e-9), vmax=vmax) if log_scale else None
    text_flip = (max(vmin, 1e-9) * vmax) ** 0.5 if log_scale else (
        vmin + (vmax - vmin) * 0.62
    )

    height = max(7.0, len(rows) * 0.58)
    fig, ax = plt.subplots(figsize=(12, height), constrained_layout=True)
    fig.suptitle(f"{title} - {run_id}", fontsize=15)
    image = ax.imshow(matrix, aspect="auto", cmap=cmap, norm=norm)

    ax.set_xticks(np.arange(len(numerator_fields)))
    ax.set_xticklabels(phase_labels, fontsize=9)
    ax.set_yticks(np.arange(len(rows)))
    ax.set_yticklabels(labels, fontsize=9)
    ax.set_xlabel("Certificate generation phase")
    ax.set_ylabel("Certificate")
    ax.grid(which="minor", color="#ffffff", linewidth=1.2)
    ax.set_xticks(np.arange(-0.5, len(numerator_fields), 1), minor=True)
    ax.set_yticks(np.arange(-0.5, len(rows), 1), minor=True)
    ax.tick_params(which="minor", bottom=False, left=False)

    for y in range(matrix.shape[0]):
        for x in range(matrix.shape[1]):
            value = matrix[y, x]
            if np.isnan(value):
                continue
            ax.text(
                x, y, format_density(value),
                ha="center",
                va="center",
                fontsize=8,
                color="#f8fafc" if value >= text_flip else "#111827",
            )

    colorbar = fig.colorbar(image, ax=ax, fraction=0.028, pad=0.02)
    colorbar.set_label(colorbar_label)

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return True


def plot_phase_cpi_per_cpu_ms(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    return plot_phase_density_heatmap(
        rows,
        output,
        run_id,
        PHASE_CPI_FIELDS,
        PHASE_FIELDS,
        "Board certgen CPICNT density by phase",
        "CPICNT delta per CPU ms (log color scale)",
    )


def plot_phase_lsu_per_cpu_ms(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    return plot_phase_density_heatmap(
        rows,
        output,
        run_id,
        PHASE_LSU_FIELDS,
        PHASE_FIELDS,
        "Board certgen LSUCNT density by phase",
        "LSUCNT delta per CPU ms (log color scale)",
    )


def plot_phase_lsu_per_cpi(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    return plot_phase_density_heatmap(
        rows,
        output,
        run_id,
        PHASE_LSU_FIELDS,
        PHASE_CPI_FIELDS,
        "Board certgen LSUCNT per CPICNT by phase",
        "LSUCNT / CPICNT",
        log_scale=False,
    )


def plot_phase_core_cycles_per_cpi(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    return plot_phase_density_heatmap(
        rows,
        output,
        run_id,
        PHASE_CORE_FIELDS,
        PHASE_CPI_FIELDS,
        "Board certgen DWT cycles per CPICNT event by phase",
        "DWT CYCCNT delta / CPICNT delta (log color scale)",
    )


def plot_phase_ratio_percent(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
    numerator_fields: list[tuple[str, str, str]],
    title: str,
    colorbar_label: str,
) -> bool:
    return plot_phase_density_heatmap(
        rows,
        output,
        run_id,
        numerator_fields,
        PHASE_CORE_FIELDS,
        title,
        colorbar_label,
        log_scale=False,
        scale=100.0,
    )


def plot_phase_lsu_per_core_percent(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    return plot_phase_ratio_percent(
        rows,
        output,
        run_id,
        PHASE_LSU_FIELDS,
        "Board certgen LSUCNT pressure by phase",
        "LSUCNT / CYCCNT (%)",
    )


def plot_phase_cpi_per_core_percent(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    return plot_phase_ratio_percent(
        rows,
        output,
        run_id,
        PHASE_CPI_FIELDS,
        "Board certgen CPICNT pressure by phase",
        "CPICNT / CYCCNT (%)",
    )


def plot_phase_exc_per_core_percent(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    return plot_phase_ratio_percent(
        rows,
        output,
        run_id,
        PHASE_EXC_FIELDS,
        "Board certgen exception pressure by phase",
        "EXCCNT / CYCCNT (%)",
    )


def plot_phase_sleep_per_core_percent(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    return plot_phase_ratio_percent(
        rows,
        output,
        run_id,
        PHASE_SLEEP_FIELDS,
        "Board certgen sleep pressure by phase",
        "SLEEPCNT / CYCCNT (%)",
    )


def plot_phase_fold_per_core_percent(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    return plot_phase_ratio_percent(
        rows,
        output,
        run_id,
        PHASE_FOLD_FIELDS,
        "Board certgen folded-instruction events by phase",
        "FOLDCNT / CYCCNT (%)",
    )


def plot_server_resource_metrics(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    fields = [
        field
        for _title, panel_fields, _xlabel in SERVER_RESOURCE_PANELS
        for field, _label, _color in panel_fields
    ]
    rows = sort_rows([
        row for row in positive_rows(rows, fields)
        if row.get("component") == "server_chain" or row.get("owner") == "server"
    ])
    if not rows:
        return False

    labels = [row_label(row) for row in rows]
    positions = np.arange(len(rows), dtype=float)
    height = max(7.0, len(rows) * 0.50)
    fig, axes = plt.subplots(
        1, len(SERVER_RESOURCE_PANELS),
        figsize=(max(16, len(SERVER_RESOURCE_PANELS) * 4.3), height),
        sharey=True,
        constrained_layout=True,
    )
    fig.suptitle(f"Server certificate generation Linux resource pressure - {run_id}", fontsize=15)

    for ax, (panel_title, panel_fields, xlabel) in zip(axes, SERVER_RESOURCE_PANELS):
        bar_height = min(0.26, 0.72 / len(panel_fields))
        offsets = (
            np.arange(len(panel_fields), dtype=float) -
            (len(panel_fields) - 1) / 2.0
        ) * bar_height
        plotted_values: list[float] = []
        for idx, (field, label, color) in enumerate(panel_fields):
            values = np.array(numeric(rows, field))
            positive = values > 0
            plotted_values.extend(values[positive].tolist())
            ax.barh(
                positions[positive] + offsets[idx],
                values[positive],
                height=bar_height,
                label=label,
                color=color,
                edgecolor="#111827",
                linewidth=0.25,
            )
        ax.set_title(panel_title, fontsize=11)
        ax.set_xlabel(xlabel)
        ax.grid(axis="x", linestyle=":", alpha=0.35)
        if plotted_values:
            ax.set_xscale("log")
            pad_x_axis(ax, plotted_values, log_scale=True)
        ax.legend(loc="lower right", fontsize=8)

    axes[0].set_yticks(positions)
    axes[0].set_yticklabels(labels, fontsize=9)
    axes[0].invert_yaxis()

    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return True


def plot_stacked_share(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
    fields: list[tuple[str, str, str]],
    title: str,
    xlabel: str,
) -> bool:
    rows = sort_rows(positive_rows(rows, [field for field, _label, _color in fields]))
    if not rows:
        return False

    labels = [row_label(row) for row in rows]
    positions = np.arange(len(rows))
    height = max(7.0, len(rows) * 0.46)
    fig, ax = plt.subplots(figsize=(12, height), constrained_layout=True)
    fig.suptitle(f"{title} - {run_id}", fontsize=15)

    totals = np.array([
        sum(float_or_none(row.get(field)) or 0.0 for field, _label, _color in fields)
        for row in rows
    ])
    left = np.zeros(len(rows))
    for field, label, color in fields:
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

    ax.set_xlabel(xlabel)
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


def plot_phase_heap_peak(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    return plot_stacked_absolute(
        rows,
        output,
        run_id,
        PHASE_HEAP_FIELDS,
        "Board certgen phase heap peaks",
        "Per-phase wolfSSL heap peak (KB)",
        divide_by=1024.0,
        log_scale=False,
    )


def plot_phase_main_thread_cpu(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> bool:
    rows = sort_rows(positive_rows(
        rows, [field for field, _label, _color in PHASE_MAIN_THREAD_FIELDS]
    ))
    if not rows:
        return False

    labels = [row_label(row) for row in rows]
    positions = np.arange(len(rows), dtype=float)
    height = max(7.0, len(rows) * 0.68)
    fig, ax = plt.subplots(figsize=(13, height), constrained_layout=True)
    fig.suptitle(f"Board certgen main-thread CPU by phase - {run_id}", fontsize=15)

    bar_height = min(0.13, 0.72 / len(PHASE_MAIN_THREAD_FIELDS))
    offsets = (
        np.arange(len(PHASE_MAIN_THREAD_FIELDS), dtype=float)
        - (len(PHASE_MAIN_THREAD_FIELDS) - 1) / 2.0
    ) * bar_height
    for idx, (field, label, color) in enumerate(PHASE_MAIN_THREAD_FIELDS):
        values = np.array(numeric(rows, field))
        positive = values > 0
        ax.barh(
            positions[positive] + offsets[idx],
            values[positive],
            height=bar_height,
            label=label,
            color=color,
            edgecolor="#111827",
            linewidth=0.25,
        )

    ax.set_xlabel("Main thread CPU share during phase (%)")
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
            plot_phase_cpu_vs_cpi_share,
            out_dir / f"certificate_phase_cpu_vs_cpi_share.{extension}",
        ),
        (
            plot_board_cpu_efficiency,
            out_dir / f"certificate_board_cpu_efficiency.{extension}",
        ),
        (
            plot_server_cpu_efficiency,
            out_dir / f"certificate_server_cpu_efficiency.{extension}",
        ),
        (
            plot_wall_cpu_gap,
            out_dir / f"certificate_wall_cpu_gap.{extension}",
        ),
        (
            plot_server_resource_metrics,
            out_dir / f"certificate_server_resource_pressure.{extension}",
        ),
        (
            plot_resource_pressure,
            out_dir / f"certificate_resource_pressure.{extension}",
        ),
        (
            plot_thread_cpu_breakdown,
            out_dir / f"certificate_thread_cpu_breakdown.{extension}",
        ),
        (
            plot_total_cpi,
            out_dir / f"certificate_total_cpi_log.{extension}",
        ),
        (
            plot_phase_wall_heatmap,
            out_dir / f"certificate_phase_wall_absolute.{extension}",
        ),
        (
            plot_server_phase_wall_ms,
            out_dir / f"certificate_server_phase_wall_absolute.{extension}",
        ),
        (
            lambda rows, path, run_id: plot_stacked_share(
                rows,
                path,
                run_id,
                PHASE_LSU_FIELDS,
                "Board certgen LSUCNT phase share",
                "Share of phase LSUCNT delta (%)",
            ),
            out_dir / f"certificate_phase_lsu_share.{extension}",
        ),
        (
            lambda rows, path, run_id: plot_stacked_share(
                rows,
                path,
                run_id,
                PHASE_CPI_FIELDS,
                "Board certgen CPICNT phase share",
                "Share of phase CPICNT delta (%)",
            ),
            out_dir / f"certificate_phase_cpi_share.{extension}",
        ),
        (
            lambda rows, path, run_id: plot_stacked_share(
                rows,
                path,
                run_id,
                PHASE_EXC_FIELDS,
                "Board certgen EXCCNT phase share",
                "Share of phase exception counter delta (%)",
            ),
            out_dir / f"certificate_phase_exc_share.{extension}",
        ),
        (
            lambda rows, path, run_id: plot_stacked_share(
                rows,
                path,
                run_id,
                PHASE_SLEEP_FIELDS,
                "Board certgen SLEEPCNT phase share",
                "Share of phase sleep counter delta (%)",
            ),
            out_dir / f"certificate_phase_sleep_share.{extension}",
        ),
        (
            lambda rows, path, run_id: plot_stacked_share(
                rows,
                path,
                run_id,
                PHASE_FOLD_FIELDS,
                "Board certgen FOLDCNT phase share",
                "Share of phase folded-instruction events (%)",
            ),
            out_dir / f"certificate_phase_fold_share.{extension}",
        ),
        (
            plot_phase_cpi_per_cpu_ms,
            out_dir / f"certificate_phase_cpi_per_cpu_ms.{extension}",
        ),
        (
            plot_phase_lsu_per_cpu_ms,
            out_dir / f"certificate_phase_lsu_per_cpu_ms.{extension}",
        ),
        (
            plot_phase_lsu_per_cpi,
            out_dir / f"certificate_phase_lsu_per_cpi.{extension}",
        ),
        (
            plot_phase_core_cycles_per_cpi,
            out_dir / f"certificate_phase_core_cycles_per_cpi.{extension}",
        ),
        (
            plot_phase_lsu_per_core_percent,
            out_dir / f"certificate_phase_lsu_per_core_percent.{extension}",
        ),
        (
            plot_phase_cpi_per_core_percent,
            out_dir / f"certificate_phase_cpi_per_core_percent.{extension}",
        ),
        (
            plot_phase_exc_per_core_percent,
            out_dir / f"certificate_phase_exc_per_core_percent.{extension}",
        ),
        (
            plot_phase_sleep_per_core_percent,
            out_dir / f"certificate_phase_sleep_per_core_percent.{extension}",
        ),
        (
            plot_phase_fold_per_core_percent,
            out_dir / f"certificate_phase_fold_per_core_percent.{extension}",
        ),
        (
            plot_phase_heap_peak,
            out_dir / f"certificate_phase_heap_peak.{extension}",
        ),
        (
            plot_phase_main_thread_cpu,
            out_dir / f"certificate_phase_main_thread_cpu.{extension}",
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
