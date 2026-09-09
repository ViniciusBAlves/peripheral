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
    from matplotlib.patches import Ellipse
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
PQC_SIG_PREFIXES = ("ML-DSA", "SLH-DSA", "LMS", "XMSS")
SECURITY_LEVELS = (1, 3, 5)
HANDSHAKE_HEATMAP_MAX_MS = 10000
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


def pki_category(row: dict[str, str]) -> str:
    """Classify current and legacy rows as homogeneous or heterogeneous PKI."""
    kind = row.get("pki_kind", "").strip().lower()
    chain_id = row.get("pki_chain_id", "").strip().lower()
    if kind.startswith("homogeneous") or chain_id.startswith("homogeneous_"):
        return "homogeneous"
    if kind in {"heavy_root", "heterogeneous", "heterogeneous_x509"}:
        return "heterogeneous"

    algorithms = [
        row.get(field, "").strip()
        for field in ("root_sig_alg", "intermediate_sig_alg", "leaf_sig_alg")
        if row.get(field, "").strip()
    ]
    if algorithms and len(set(algorithms)) > 1:
        return "heterogeneous"
    # Older result schemas had no PKI metadata and represented one algorithm.
    return "homogeneous"


def pki_signature_label(row: dict[str, str]) -> str:
    """Keep distinct heterogeneous roots from collapsing into one heatmap row."""
    leaf = row.get("leaf_sig_alg") or row.get("cert_sig_alg", "")
    if pki_category(row) == "homogeneous":
        return leaf
    root = row.get("root_sig_alg", "")
    return f"{root} -> {leaf}" if root and leaf else row.get("pki_chain_id", leaf)


def scatter_certificate_algorithm(row: dict[str, str]) -> str:
    """Group scatter plots by root algorithm, with legacy-data fallbacks."""
    return (
        row.get("root_sig_alg")
        or row.get("leaf_sig_alg")
        or row.get("cert_sig_alg", "unknown")
    )


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


def signature_security_level(row: dict[str, str]) -> int | None:
    return normalize_security_level(int_or_none(row.get("sig_nist_level")))


def algorithm_label(name: str, level: int | None) -> str:
    level_text = str(level) if level is not None else "unknown"
    return f"[{level_text}] - {name}"


def handshake_value(row: dict[str, str]) -> float | None:
    return float_or_none(
        row.get("mean_raw_handshake_ms") or row.get("mean_handshake_ms")
    )


def mean_metric(row: dict[str, str], *names: str) -> float:
    for name in names:
        value = float_or_none(row.get(name))
        if value is not None:
            return max(0.0, value)
    return 0.0


def handshake_components(row: dict[str, str]) -> tuple[float, float, float, float]:
    """Return mutually exclusive components whose sum is raw handshake time."""
    raw = handshake_value(row) or 0.0
    kem = mean_metric(row, "mean_kem_client_total_ms")
    if kem == 0.0:
        kem = sum(
            mean_metric(row, name)
            for name in (
                "mean_kem_keygen_ms",
                "mean_kem_decapsulation_ms",
                "mean_classical_kex_keygen_ms",
                "mean_classical_kex_shared_secret_ms",
            )
        )

    signature = mean_metric(row, "mean_client_signature_total_ms")
    if signature == 0.0:
        signature = sum(
            mean_metric(row, name)
            for name in (
                "mean_x509_chain_signature_verify_ms",
                "mean_tls_certificate_verify_signature_verify_ms",
                "mean_mtls_signature_generate_ms",
            )
        )
    if signature == 0.0:
        signature = mean_metric(row, "mean_certificate_signature_verify_ms")

    communication = mean_metric(row, "mean_communication_overhead_ms")
    measured_total = kem + signature + communication

    # The instrumented intervals should be disjoint. Normalize defensively if
    # measurements overlap so the visual decomposition still equals raw time.
    if measured_total > raw and measured_total > 0.0:
        scale = raw / measured_total
        kem *= scale
        signature *= scale
        communication *= scale

    cpu_active_other = max(0.0, raw - kem - signature - communication)
    return kem, signature, cpu_active_other, communication


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

        def attempt_mean(field: str) -> str:
            metric_values = [
                value
                for attempt in successes
                if (value := float_or_none(attempt.get(field))) is not None
            ]
            return (
                f"{statistics.mean(metric_values):.3f}"
                if metric_values
                else ""
            )

        stddev = statistics.stdev(values) if len(values) > 1 else 0.0
        rows.append(
            {
                "case_id": attempts_csv.parent.name.split("_", 1)[-1],
                "pki_chain_id": first.get("pki_chain_id", ""),
                "pki_kind": first.get("pki_kind", ""),
                "root_sig_alg": first.get("root_sig_alg", ""),
                "intermediate_sig_alg": first.get("intermediate_sig_alg", ""),
                "leaf_sig_alg": first.get("leaf_sig_alg", ""),
                "kex_group": first.get("kex_group", ""),
                "kex_nist_level": first.get("kex_nist_level", ""),
                "cert_sig_alg": first.get("cert_sig_alg", ""),
                "sig_nist_level": first.get("sig_nist_level", ""),
                "mean_handshake_ms": f"{statistics.mean(values):.3f}",
                "stddev_raw_handshake_ms": f"{stddev:.3f}",
                "success_count": str(len(successes)),
                "mean_kem_client_total_ms": attempt_mean(
                    "kem_client_total_ms"
                ),
                "mean_client_signature_total_ms": attempt_mean(
                    "client_signature_total_ms"
                ),
                "mean_communication_overhead_ms": attempt_mean(
                    "communication_overhead_ms"
                ),
                "mean_client_cpu_ms": attempt_mean("client_cpu_ms"),
                "mean_average_cpu_usage_percent": attempt_mean(
                    "average_cpu_usage_percent"
                ),
                "mean_l2cap_tx_bytes": attempt_mean("l2cap_tx_bytes"),
                "mean_l2cap_rx_bytes": attempt_mean("l2cap_rx_bytes"),
                "mean_l2cap_tx_wait_ms": attempt_mean("l2cap_tx_wait_ms"),
                "mean_x509_chain_signature_verify_ms": attempt_mean(
                    "x509_chain_signature_verify_ms"
                ),
                "mean_tls_certificate_verify_signature_verify_ms": attempt_mean(
                    "tls_certificate_verify_signature_verify_ms"
                ),
                "mean_mtls_signature_generate_ms": attempt_mean(
                    "mtls_signature_generate_ms"
                ),
                "mean_client_icache_hit_percent": attempt_mean(
                    "client_icache_hit_percent"
                ),
                "mean_client_icache_miss_percent": attempt_mean(
                    "client_icache_miss_percent"
                ),
                "mean_handshake_energy_uj": attempt_mean(
                    "handshake_energy_uj"
                ),
                "mean_client_kem_energy_uj": attempt_mean(
                    "client_kem_energy_uj"
                ),
                "mean_client_signature_energy_uj": attempt_mean(
                    "client_signature_energy_uj"
                ),
                "firmware_static_ram_used_bytes": first.get(
                    "firmware_static_ram_used_bytes", ""
                ),
                "firmware_ram_capacity_bytes": first.get(
                    "firmware_ram_capacity_bytes", ""
                ),
                "firmware_static_ram_usage_percent": first.get(
                    "firmware_static_ram_usage_percent", ""
                ),
                "server_chain_bytes": first.get("server_chain_bytes", ""),
            }
        )
    return rows


def add_attempt_resource_metrics(
    rows: list[dict[str, str]], run_dir: Path
) -> None:
    rows_by_case = {row.get("case_id", ""): row for row in rows}
    for attempts_csv in sorted((run_dir / "cases").glob("*/attempts.csv")):
        case_id = attempts_csv.parent.name.split("_", 1)[-1]
        target = rows_by_case.get(case_id)
        if target is None:
            continue
        with attempts_csv.open(newline="") as fp:
            attempts = list(csv.DictReader(fp))
            cpu_values = [
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
            cache_values = [
                value
                for attempt in attempts
                if attempt.get("status") == "success"
                and attempt.get("warmup") != "1"
                and (
                    value := float_or_none(
                        attempt.get("client_icache_hit_percent")
                    )
                ) is not None
            ]
            heap_values = [
                value
                for attempt in attempts
                if attempt.get("status") == "success"
                and attempt.get("warmup") != "1"
                and (
                    value := float_or_none(
                        attempt.get("client_heap_peak_bytes")
                    )
                ) is not None
            ]
            stack_values = [
                value
                for attempt in attempts
                if attempt.get("status") == "success"
                and attempt.get("warmup") != "1"
                and (
                    value := float_or_none(
                        attempt.get("thread_stack_used_bytes")
                    )
                ) is not None
            ]
        if cpu_values:
            target["mean_system_cpu_usage_percent"] = (
                f"{statistics.mean(cpu_values):.3f}"
            )
        if cache_values and not float_or_none(
            target.get("mean_client_icache_hit_percent")
        ):
            target["mean_client_icache_hit_percent"] = (
                f"{statistics.mean(cache_values):.3f}"
            )
        if heap_values:
            target["max_client_heap_peak_bytes"] = f"{max(heap_values):.3f}"
        if stack_values:
            target["max_thread_stack_used_bytes"] = f"{max(stack_values):.3f}"


def add_total_memory_metrics(rows: list[dict[str, str]]) -> None:
    """Derive occupied RAM without counting reserved heap and stacks twice."""
    for row in rows:
        static_used = float_or_none(row.get("firmware_static_ram_used_bytes"))
        capacity = float_or_none(row.get("firmware_ram_capacity_bytes"))
        heap_capacity = float_or_none(row.get("client_heap_capacity_bytes"))
        heap_peak = float_or_none(row.get("max_client_heap_peak_bytes"))
        stack_capacity = float_or_none(row.get("thread_stack_capacity_bytes"))
        stack_used = float_or_none(row.get("max_thread_stack_used_bytes"))
        if None in (
            static_used, capacity, heap_capacity, heap_peak,
            stack_capacity, stack_used,
        ) or capacity == 0:
            continue
        total_used = (
            static_used - heap_capacity - stack_capacity + heap_peak + stack_used
        )
        row["total_memory_used_bytes"] = f"{total_used:.3f}"
        row["total_memory_usage_percent"] = f"{100.0 * total_used / capacity:.3f}"


def load_rows(run_dir: Path) -> list[dict[str, str]]:
    rows = load_from_summary(run_dir / "summary.csv")
    if rows:
        add_attempt_resource_metrics(rows, run_dir)
        add_total_memory_metrics(rows)
        return rows
    rows = load_from_attempts(run_dir)
    add_attempt_resource_metrics(rows, run_dir)
    add_total_memory_metrics(rows)
    return rows


def load_reconnect_count_rows(run_dir: Path) -> list[dict[str, str]]:
    """Load one row per case with total reconnects across all attempts."""
    rows_by_case: dict[str, dict[str, str]] = {}
    input_cases = run_dir / "input_cases.csv"
    if input_cases.exists():
        with input_cases.open(newline="") as fp:
            rows_by_case = {
                row["case_id"]: dict(row)
                for row in csv.DictReader(fp)
                if row.get("case_id")
            }

    summary_csv = run_dir / "summary.csv"
    if summary_csv.exists():
        with summary_csv.open(newline="") as fp:
            for row in csv.DictReader(fp):
                case_id = row.get("case_id", "")
                if not case_id:
                    continue
                target = rows_by_case.setdefault(case_id, {})
                target.update(
                    {
                        key: value
                        for key, value in row.items()
                        if value != "" or key not in target
                    }
                )

    for attempts_csv in sorted((run_dir / "cases").glob("*/attempts.csv")):
        case_id = attempts_csv.parent.name.split("_", 1)[-1]
        with attempts_csv.open(newline="") as fp:
            attempts = list(csv.DictReader(fp))
        target = rows_by_case.setdefault(case_id, {"case_id": case_id})
        if attempts:
            for key in (
                "kex_group", "kex_nist_level", "cert_sig_alg",
                "sig_nist_level",
            ):
                if not target.get(key):
                    target[key] = attempts[0].get(key, "")
        target["reconnect_count_total"] = str(
            sum(int_or_none(attempt.get("reconnect_count")) or 0 for attempt in attempts)
        )

    rows: list[dict[str, str]] = []
    for row in rows_by_case.values():
        if row.get("kex_group") and row.get("cert_sig_alg"):
            if int_or_none(row.get("reconnect_count_total")) is None:
                row["reconnect_count_total"] = "0"
            rows.append(row)
    return rows


def short_label(row: dict[str, str]) -> str:
    kex = row.get("kex_group", "")
    sig = pki_signature_label(row)
    return (
        f"{algorithm_label(kex, kem_security_level(row))}\n"
        f"{algorithm_label(sig, signature_security_level(row))}"
    )


def plot_algorithm_metric(
    rows: list[dict[str, str]],
    *,
    algorithm_field: str,
    level_field: str,
    metric_field: str,
    title: str,
    ylabel: str,
    color: str,
    output: Path,
) -> int:
    """Plot one averaged bar per algorithm instead of per KEM/signature pair."""
    values_by_algorithm: dict[str, list[float]] = defaultdict(list)
    levels_by_algorithm: dict[str, int | None] = {}
    for row in rows:
        algorithm = (
            pki_signature_label(row)
            if algorithm_field == "pki_signature_label"
            else row.get(algorithm_field, "")
        )
        value = float_or_none(row.get(metric_field))
        if value is None:
            components = handshake_components(row)
            if metric_field == "mean_kem_client_total_ms":
                value = components[0]
            elif metric_field == "mean_client_signature_total_ms":
                value = components[1]
        if not algorithm or value is None:
            continue
        values_by_algorithm[algorithm].append(value)
        levels_by_algorithm[algorithm] = normalize_security_level(
            int_or_none(row.get(level_field))
        )

    if not values_by_algorithm:
        print(f"warning: no values found for {metric_field}")
        return 0

    algorithms = sorted(
        values_by_algorithm,
        key=lambda name: (
            -statistics.mean(values_by_algorithm[name]),
            name.lower(),
        ),
    )
    values = [
        statistics.mean(values_by_algorithm[name]) for name in algorithms
    ]
    labels = [
        algorithm_label(name, levels_by_algorithm[name])
        for name in algorithms
    ]
    count = len(algorithms)
    fig_width = max(10, count * 1.15)
    fig, ax = plt.subplots(
        figsize=(fig_width, 8.5),
        constrained_layout=True,
    )
    bars = ax.bar(
        range(count),
        values,
        width=1.0,
        color=color,
        edgecolor="#1a1a1a",
        linewidth=0.35,
    )
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    ax.set_xlabel("Algorithm")
    ax.set_xticks(range(count))
    ax.set_xticklabels(labels, rotation=55, ha="right", fontsize=9)
    ax.set_xlim(-0.5, count - 0.5)
    ax.margins(x=0)
    ax.grid(axis="y", linestyle=":", alpha=0.35)
    for bar, value in zip(bars, values):
        ax.annotate(
            f"{value:.2f}",
            xy=(bar.get_x() + bar.get_width() / 2, value),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=8,
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return count


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
    components = [handshake_components(row) for row in rows]
    component_labels = (
        "Client KEM",
        "Client Signature",
        "Active CPU",
        "Communication Overhead",
    )
    component_colors = ("#2a9d8f", "#e9c46a", "#457b9d", "#e76f51")
    bottoms = np.zeros(len(values))
    top_bars = None
    for component_index, (component_label, color) in enumerate(
        zip(component_labels, component_colors)
    ):
        heights = [parts[component_index] for parts in components]
        top_bars = ax.bar(
            range(len(values)),
            heights,
            width=1.0,
            bottom=bottoms,
            label=component_label,
            color=color,
            edgecolor="#1a1a1a",
            linewidth=0.25,
        )
        bottoms += np.asarray(heights)

    ax.errorbar(
        range(len(values)),
        values,
        yerr=errors,
        fmt="none",
        ecolor="#111111",
        elinewidth=0.8,
        capsize=2.0,
        capthick=0.8,
        zorder=5,
    )

    ax.set_title(title)
    ax.set_ylabel("Raw TLS handshake decomposition (ms), with 95% CI")
    ax.set_xlabel("KEM / certificate signature")
    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, rotation=72, ha="right", fontsize=label_font)
    ax.set_xlim(-0.5, len(values) - 0.5)
    ax.margins(x=0)
    ax.grid(axis="y", linestyle=":", alpha=0.35)
    ax.legend(loc="upper right", fontsize=max(8, label_font - 2), ncol=2)

    assert top_bars is not None
    for bar, value in zip(top_bars, values):
        ax.annotate(
            f"{value:.0f}",
            xy=(bar.get_x() + bar.get_width() / 2, value),
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
                f"{title_prefix} - {level} - {run_id}",
                out_dir / f"{filename_prefix}_nist_level_{level}.{extension}",
            )
    return counts


def plot_cpu_vs_handshake(
    rows: list[dict[str, str]], output: Path, run_id: str, pki: str,
    color_by_certificate: dict[str, object],
) -> int:
    """Summarize CPU/handshake ranges across KEMs with one ellipse per DSA."""
    certificates = sorted({
        scatter_certificate_algorithm(row) for row in rows
    })
    fig, ax = plt.subplots(figsize=(9, 8), constrained_layout=True)
    count = 0
    limits: list[float] = [0.0]
    for certificate in certificates:
        points = [
            (mean_metric(row, "mean_client_cpu_ms"), handshake_value(row))
            for row in rows
            if scatter_certificate_algorithm(row) == certificate
        ]
        points = [(x, y) for x, y in points if x > 0 and y is not None]
        if not points:
            continue
        x_values, y_values = zip(*points)
        limits.extend(x_values)
        limits.extend(y_values)
        x_min, x_max = min(x_values), max(x_values)
        y_min, y_max = min(y_values), max(y_values)
        color = color_by_certificate[certificate]
        ax.add_patch(Ellipse(
            ((x_min + x_max) / 2.0, (y_min + y_max) / 2.0),
            width=x_max - x_min,
            height=y_max - y_min,
            facecolor=(*color[:3], 0.32), edgecolor=color,
            linewidth=1.4, label=certificate,
        ))
        ax.update_datalim(((x_min, y_min), (x_max, y_max)))
        count += 1
    maximum = max(limits) * 1.03
    ax.plot([0, maximum], [0, maximum], linestyle="--", color="#333333",
            linewidth=1.0, label="y = x")
    ax.set_xlim(0, maximum)
    ax.set_ylim(0, maximum)
    ax.set_title(
        f"Active client CPU time vs TLS handshake time "
        f"({pki.capitalize()} PKI) - {run_id}"
    )
    ax.set_xlabel("Mean active client CPU time (ms)")
    ax.set_ylabel("Mean raw TLS handshake time (ms)")
    ax.grid(linestyle=":", alpha=0.35)
    ax.legend(title="Root certificate algorithm", fontsize=7, ncol=2)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return count


def plot_heap_vs_handshake(
    rows: list[dict[str, str]], output: Path, run_id: str, pki: str,
    color_by_certificate: dict[str, object],
) -> int:
    """Summarize heap/handshake ranges across KEMs with one ellipse per DSA."""
    leaves = sorted({
        scatter_certificate_algorithm(row) for row in rows
    })
    fig, ax = plt.subplots(figsize=(10, 8), constrained_layout=True)
    count = 0
    for leaf in leaves:
        points = []
        for row in rows:
            heap = float_or_none(row.get("max_client_heap_peak_bytes"))
            handshake = handshake_value(row)
            if (scatter_certificate_algorithm(row) == leaf
                    and heap is not None and handshake is not None):
                points.append((heap / 1024.0, handshake))
        if not points:
            continue
        x_values, y_values = zip(*points)
        x_min, x_max = min(x_values), max(x_values)
        y_min, y_max = min(y_values), max(y_values)
        color = color_by_certificate[leaf]
        ax.add_patch(Ellipse(
            ((x_min + x_max) / 2.0, (y_min + y_max) / 2.0),
            width=x_max - x_min,
            height=y_max - y_min,
            facecolor=(*color[:3], 0.32), edgecolor=color,
            linewidth=1.4, label=leaf,
        ))
        ax.update_datalim(((x_min, y_min), (x_max, y_max)))
        count += 1
    ax.autoscale_view()
    ax.set_title(
        f"Peak wolfSSL heap vs TLS handshake time "
        f"({pki.capitalize()} PKI) - {run_id}"
    )
    ax.set_xlabel("Peak wolfSSL heap allocation (KiB)")
    ax.set_ylabel("Mean raw TLS handshake time (ms)")
    ax.grid(linestyle=":", alpha=0.35)
    ax.legend(title="Root certificate algorithm", fontsize=7, ncol=2)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return count


def residual_components(row: dict[str, str]) -> tuple[float, ...]:
    raw = handshake_value(row) or 0.0
    components = (
        mean_metric(row, "mean_kem_client_total_ms"),
        mean_metric(row, "mean_x509_chain_signature_verify_ms"),
        mean_metric(row, "mean_tls_certificate_verify_signature_verify_ms"),
        mean_metric(row, "mean_mtls_signature_generate_ms"),
        mean_metric(row, "mean_communication_overhead_ms"),
    )
    residual = raw - sum(components)
    return (*components, residual)


def plot_nist_residual_bars(
    rows: list[dict[str, str]], output: Path, run_id: str,
    pki: str, level: int,
) -> int:
    rows = sorted(rows, key=lambda row: handshake_value(row) or 0.0, reverse=True)
    if not rows:
        return 0
    labels = [
        f"{row.get('kex_group', '')}\n{pki_signature_label(row)}" for row in rows
    ]
    names = (
        "Client KEM", "X.509 chain verify", "CertificateVerify verify",
        "mTLS sign", "Communication", "Residual",
    )
    colors = ("#2a9d8f", "#e9c46a", "#f4a261", "#bc6c25", "#e76f51", "#457b9d")
    positions = np.arange(len(rows))
    bottoms = np.zeros(len(rows))
    fig_width = max(12.0, min(44.0, len(rows) * 0.55))
    fig, ax = plt.subplots(figsize=(fig_width, 9), constrained_layout=True)
    for index, (name, color) in enumerate(zip(names, colors)):
        heights = np.asarray([residual_components(row)[index] for row in rows])
        ax.bar(
            positions, heights, width=1.0, bottom=bottoms, label=name,
            color=color, edgecolor="#1a1a1a", linewidth=0.25,
        )
        bottoms += heights
    ax.set_title(
        f"TLS handshake decomposition - KEM NIST level {level} - "
        f"{pki.capitalize()} PKI - {run_id}"
    )
    ax.set_ylabel("Mean raw TLS handshake time (ms)")
    ax.set_xlabel("KEM / PKI signature chain")
    ax.set_xticks(positions)
    ax.set_xticklabels(labels, rotation=70, ha="right", fontsize=7)
    ax.set_xlim(-0.5, len(rows) - 0.5)
    ax.margins(x=0)
    ax.grid(axis="y", linestyle=":", alpha=0.35)
    ax.legend(fontsize=8, ncol=2)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return len(rows)


CORRELATION_FIELDS = (
    ("raw_handshake_ms", "Raw handshake"),
    ("handshake_energy_uj", "Handshake energy"),
    ("client_kem_energy_uj", "Client KEM energy"),
    ("client_signature_energy_uj", "Client signature energy"),
    ("client_cpu_ms", "Client CPU"),
    ("client_heap_peak_bytes", "Heap peak"),
    ("server_chain_bytes", "Server chain"),
    ("l2cap_tx_bytes", "L2CAP TX"),
    ("l2cap_rx_bytes", "L2CAP RX"),
    ("l2cap_tx_wait_ms", "L2CAP TX wait"),
    ("communication_overhead_ms", "Communication"),
    ("x509_chain_signature_verify_ms", "X.509 verify"),
    ("tls_certificate_verify_signature_verify_ms", "CertificateVerify"),
    ("client_icache_miss_percent", "I-cache miss"),
)


def correlation_value(row: dict[str, str], field: str) -> float | None:
    if field == "raw_handshake_ms":
        return handshake_value(row)
    mappings = {
        "handshake_energy_uj": "mean_handshake_energy_uj",
        "client_kem_energy_uj": "mean_client_kem_energy_uj",
        "client_signature_energy_uj": "mean_client_signature_energy_uj",
        "client_cpu_ms": "mean_client_cpu_ms",
        "client_heap_peak_bytes": "max_client_heap_peak_bytes",
        "l2cap_tx_bytes": "mean_l2cap_tx_bytes",
        "l2cap_rx_bytes": "mean_l2cap_rx_bytes",
        "l2cap_tx_wait_ms": "mean_l2cap_tx_wait_ms",
        "communication_overhead_ms": "mean_communication_overhead_ms",
        "x509_chain_signature_verify_ms": "mean_x509_chain_signature_verify_ms",
        "tls_certificate_verify_signature_verify_ms": (
            "mean_tls_certificate_verify_signature_verify_ms"
        ),
        "client_icache_miss_percent": "mean_client_icache_miss_percent",
    }
    return float_or_none(row.get(mappings.get(field, field)))


def rank_values(values: np.ndarray) -> np.ndarray:
    order = np.argsort(values, kind="mergesort")
    ranks = np.empty(len(values), dtype=float)
    start = 0
    while start < len(values):
        end = start + 1
        while end < len(values) and values[order[end]] == values[order[start]]:
            end += 1
        ranks[order[start:end]] = (start + end - 1) / 2.0 + 1.0
        start = end
    return ranks


def plot_spearman_matrix(
    rows: list[dict[str, str]], output: Path, csv_output: Path, run_id: str
) -> int:
    size = len(CORRELATION_FIELDS)
    matrix = np.full((size, size), np.nan)
    for row_index, (field_a, _) in enumerate(CORRELATION_FIELDS):
        for column_index, (field_b, _) in enumerate(CORRELATION_FIELDS):
            pairs = [
                (a, b) for row in rows
                if (a := correlation_value(row, field_a)) is not None
                and (b := correlation_value(row, field_b)) is not None
            ]
            if len(pairs) < 3:
                continue
            a_values = rank_values(np.asarray([a for a, _ in pairs]))
            b_values = rank_values(np.asarray([b for _, b in pairs]))
            if np.std(a_values) > 0 and np.std(b_values) > 0:
                matrix[row_index, column_index] = np.corrcoef(a_values, b_values)[0, 1]
    labels = [label for _, label in CORRELATION_FIELDS]
    fig, ax = plt.subplots(figsize=(14, 12), constrained_layout=True)
    image = ax.imshow(matrix, cmap="coolwarm", vmin=-1, vmax=1)
    ax.set_title(f"Spearman correlation matrix - {run_id}")
    ax.set_xticks(range(size), labels=labels, rotation=55, ha="right", fontsize=8)
    ax.set_yticks(range(size), labels=labels, fontsize=8)
    for row_index in range(size):
        for column_index in range(size):
            value = matrix[row_index, column_index]
            if not np.isnan(value):
                ax.text(column_index, row_index, f"{value:.2f}",
                        ha="center", va="center", fontsize=8,
                        color="white" if abs(value) > 0.55 else "black")
    fig.colorbar(image, ax=ax).set_label("Spearman rho")
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    with csv_output.open("w", newline="") as stream:
        writer = csv.writer(stream)
        writer.writerow(("metric", *[field for field, _ in CORRELATION_FIELDS]))
        for (field, _), values in zip(CORRELATION_FIELDS, matrix):
            writer.writerow((field, *[
                "" if np.isnan(value) else f"{value:.6f}" for value in values
            ]))
    return len(rows)


def plot_heatmap(rows: list[dict[str, str]], output: Path, run_id: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    values_by_pair: dict[tuple[str, str], list[float]] = defaultdict(list)
    ci_by_pair: dict[tuple[str, str], list[float]] = defaultdict(list)
    for row in rows:
        kex = row.get("kex_group", "")
        sig = pki_signature_label(row)
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
    kem_levels = {
        row.get("kex_group", ""): kem_security_level(row) for row in rows
    }
    sig_levels = {
        pki_signature_label(row): signature_security_level(row)
        for row in rows
    }
    ax.set_xticklabels(
        [algorithm_label(kem, kem_levels.get(kem)) for kem in kems],
        rotation=55, ha="right", fontsize=7,
    )
    ax.set_yticklabels(
        [algorithm_label(sig, sig_levels.get(sig)) for sig in sigs],
        fontsize=7,
    )
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
                    color="black",
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
    colorbar_label: str = "Usage (%)",
    vmin: float | None = 0,
    vmax: float | None = 100,
) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    values_by_pair: dict[tuple[str, str], list[float]] = defaultdict(list)
    for row in rows:
        kex = row.get("kex_group", "")
        sig = pki_signature_label(row)
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
    kem_levels = {
        row.get("kex_group", ""): kem_security_level(row) for row in rows
    }
    sig_levels = {
        pki_signature_label(row): signature_security_level(row)
        for row in rows
    }
    ax.set_xticklabels(
        [algorithm_label(kem, kem_levels.get(kem)) for kem in kems],
        rotation=55, ha="right", fontsize=7,
    )
    ax.set_yticklabels(
        [algorithm_label(sig, sig_levels.get(sig)) for sig in sigs],
        fontsize=7,
    )
    for row_idx in range(len(sigs)):
        for col_idx in range(len(kems)):
            value = matrix[row_idx, col_idx]
            if not np.isnan(value):
                ax.text(
                    col_idx, row_idx,
                    f"{value:.{value_decimals}f}{value_suffix}",
                    ha="center", va="center", fontsize=11,
                    color="black",
                )
    colorbar = fig.colorbar(image, ax=ax)
    colorbar.set_label(colorbar_label)
    fig.savefig(output, dpi=180)
    plt.close(fig)
    return len(values_by_pair)


def plot_reconnect_count_heatmap(
    rows: list[dict[str, str]],
    output: Path,
    run_id: str,
) -> int:
    return plot_percent_heatmap(
        rows,
        "reconnect_count_total",
        f"Reconnects per case - {run_id}",
        output,
        value_suffix="",
        value_decimals=0,
        colorbar_label="Reconnects",
        vmin=0,
        vmax=None,
    )


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
    out_dir = args.out_dir or (PROJECT_ROOT / "graphic" / "out" / run_dir.name)
    extension = "png" if args.generate_png else "pdf"
    chart_config = {
        "pqc_only": ("PQC-only TLS handshakes", "tls_handshake_pqc_only"),
        "classic_only": (
            "Classic-only TLS handshakes", "tls_handshake_classic_only"
        ),
        "mixed": ("Mixed / hybrid TLS handshakes", "tls_handshake_mixed"),
    }
    pki_groups = {
        pki: [row for row in plot_rows if pki_category(row) == pki]
        for pki in ("homogeneous", "heterogeneous")
    }
    heatmap_pki_groups = {
        pki: [row for row in rows if pki_category(row) == pki]
        for pki in ("homogeneous", "heterogeneous")
    }
    categories: dict[tuple[str, str], list[dict[str, str]]] = {}
    kem_bar_count = 0
    signature_bar_count = 0
    for pki, pki_rows in pki_groups.items():
        if not pki_rows:
            continue
        pki_title = f"{pki.capitalize()} PKI"
        for category in ("pqc_only", "classic_only", "mixed"):
            category_rows = [
                row for row in pki_rows if case_category(row) == category
            ]
            categories[(pki, category)] = category_rows
            if not category_rows:
                continue
            title, filename = chart_config[category]
            filename = f"{filename}_{pki}"
            full_title = f"{title} - {pki_title}"
            plot_group(
                category_rows,
                f"{full_title} - {run_dir.name}",
                out_dir / f"{filename}.{extension}",
            )
            if args.sec_levels:
                counts = plot_security_levels(
                    category_rows, full_title, filename, out_dir,
                    run_dir.name, extension,
                )
                for level in SECURITY_LEVELS:
                    print(
                        f"{pki}_{category}_nist_level_{level}="
                        f"{counts.get(level, 0)}"
                    )

        kem_bar_count += plot_algorithm_metric(
            pki_rows,
            algorithm_field="kex_group",
            level_field="kex_nist_level",
            metric_field="mean_kem_client_total_ms",
            title=f"Client KEM execution time - {pki_title} - {run_dir.name}",
            ylabel="Mean client KEM time (ms)",
            color="#2a9d8f",
            output=out_dir / f"kem_execution_time_{pki}.{extension}",
        )
        signature_bar_count += plot_algorithm_metric(
            pki_rows,
            algorithm_field="pki_signature_label",
            level_field="sig_nist_level",
            metric_field="mean_client_signature_total_ms",
            title=(
                f"Client digital-signature execution time - {pki_title} - "
                f"{run_dir.name}"
            ),
            ylabel="Mean client signature time (ms)",
            color="#e9c46a",
            output=out_dir / f"signature_execution_time_{pki}.{extension}",
        )

    certificates = sorted({
        scatter_certificate_algorithm(row) for row in rows
    })
    certificate_colors = {
        certificate: color for certificate, color in zip(
            certificates,
            plt.get_cmap("turbo")(
                np.linspace(0.03, 0.97, max(1, len(certificates)))
            ),
        )
    }
    cpu_scatter_count = 0
    heap_scatter_count = 0
    for pki, pki_rows in pki_groups.items():
        if not pki_rows:
            continue
        cpu_scatter_count += plot_cpu_vs_handshake(
            pki_rows,
            out_dir / f"scatter_client_cpu_vs_handshake_{pki}.{extension}",
            run_dir.name,
            pki,
            certificate_colors,
        )
        heap_scatter_count += plot_heap_vs_handshake(
            pki_rows,
            out_dir / f"scatter_heap_peak_vs_handshake_{pki}.{extension}",
            run_dir.name,
            pki,
            certificate_colors,
        )
    residual_bar_count = 0
    for pki, pki_rows in pki_groups.items():
        for level in SECURITY_LEVELS:
            level_rows = [
                row for row in pki_rows if kem_security_level(row) == level
            ]
            residual_bar_count += plot_nist_residual_bars(
                level_rows,
                out_dir / (
                    f"tls_handshake_residual_nist_level_{level}_{pki}."
                    f"{extension}"
                ),
                run_dir.name, pki, level,
            )
    correlation_count = plot_spearman_matrix(
        rows,
        out_dir / f"spearman_correlation_matrix.{extension}",
        out_dir / "spearman_correlation_matrix.csv",
        run_dir.name,
    )

    if args.heatmap:
        hardware_heatmaps = (
            (
                "mean_average_cpu_usage_percent",
                "Average client processing CPU usage (communication excluded) - "
                f"{run_dir.name}",
                "heatmap_cpu_processing_usage_percent",
            ),
            (
                "mean_system_cpu_usage_percent",
                f"Average system CPU usage - {run_dir.name}",
                "heatmap_cpu_average_usage_percent",
            ),
            (
                "max_client_heap_peak_usage_percent",
                f"Peak wolfSSL heap usage - {run_dir.name}",
                "heatmap_heap_peak_usage_percent",
            ),
            (
                "firmware_static_ram_usage_percent",
                f"Total firmware static RAM usage - {run_dir.name}",
                "heatmap_static_ram_usage_percent",
            ),
            (
                "total_memory_usage_percent",
                f"Total occupied RAM including peak heap and stack - {run_dir.name}",
                "heatmap_total_memory_usage_percent",
            ),
            (
                "max_thread_stack_peak_percent",
                f"Peak thread stack usage - {run_dir.name}",
                "heatmap_thread_stack_peak_percent",
            ),
        )
        reconnect_rows = load_reconnect_count_rows(run_dir)
        static_ram_capacity = max(
            (
                value
                for row in rows
                if (
                    value := float_or_none(
                        row.get("firmware_ram_capacity_bytes")
                    )
                ) is not None
            ),
            default=None,
        )
        heatmap_count = 0
        for pki, pki_rows in heatmap_pki_groups.items():
            if not pki_rows:
                continue
            pki_title = f"{pki.capitalize()} PKI"
            plot_heatmap(
                pki_rows,
                out_dir / f"tls_handshake_heatmap_{pki}.{extension}",
                f"{run_dir.name} - {pki_title}",
            )
            heatmap_count += 1
            for metric, title, filename_prefix in hardware_heatmaps:
                plotted = plot_percent_heatmap(
                    pki_rows, metric, f"{title} - {pki_title}",
                    out_dir / f"{filename_prefix}_{pki}.{extension}",
                )
                heatmap_count += int(plotted > 0)
                print(f"{pki}_{metric}_heatmap_cells={plotted}")
            static_ram_bytes_cells = plot_percent_heatmap(
                pki_rows,
                "firmware_static_ram_used_bytes",
                f"Total firmware static RAM usage in bytes - {run_dir.name} - {pki_title}",
                out_dir / f"heatmap_static_ram_used_bytes_{pki}.{extension}",
                value_suffix="",
                value_decimals=0,
                colorbar_label="Firmware static RAM used (bytes)",
                vmax=static_ram_capacity,
            )
            heatmap_count += int(static_ram_bytes_cells > 0)
            print(
                f"{pki}_firmware_static_ram_used_bytes_heatmap_cells="
                f"{static_ram_bytes_cells}"
            )
            total_memory_bytes_cells = plot_percent_heatmap(
                pki_rows,
                "total_memory_used_bytes",
                f"Total occupied RAM including peak heap and stack in bytes - {run_dir.name} - {pki_title}",
                out_dir / f"heatmap_total_memory_used_bytes_{pki}.{extension}",
                value_suffix="",
                value_decimals=0,
                colorbar_label="Total occupied RAM (bytes)",
                vmax=static_ram_capacity,
            )
            heatmap_count += int(total_memory_bytes_cells > 0)
            print(
                f"{pki}_total_memory_used_bytes_heatmap_cells="
                f"{total_memory_bytes_cells}"
            )
            cache_cells = plot_percent_heatmap(
                pki_rows,
                "mean_client_icache_hit_percent",
                f"Client instruction-cache hit rate - {run_dir.name} - {pki_title}",
                out_dir / f"heatmap_client_icache_hit_percent_{pki}.{extension}",
                colorbar_label="Mean instruction-cache hit rate (%)",
            )
            heatmap_count += int(cache_cells > 0)
            print(f"{pki}_mean_client_icache_hit_percent_heatmap_cells={cache_cells}")
            heap_bytes_cells = plot_percent_heatmap(
                pki_rows,
                "max_client_heap_peak_bytes",
                f"Peak wolfSSL heap allocation in bytes - {run_dir.name} - {pki_title}",
                out_dir / f"heatmap_client_heap_peak_bytes_{pki}.{extension}",
                value_suffix="",
                value_decimals=0,
                colorbar_label="Peak wolfSSL heap allocation (bytes)",
                vmin=None,
                vmax=None,
            )
            heatmap_count += int(heap_bytes_cells > 0)
            print(f"{pki}_max_client_heap_peak_bytes_heatmap_cells={heap_bytes_cells}")
            chain_bytes_cells = plot_percent_heatmap(
                pki_rows,
                "server_chain_bytes",
                f"Server certificate chain size - {run_dir.name} - {pki_title}",
                out_dir / f"heatmap_server_chain_bytes_{pki}.{extension}",
                value_suffix="",
                value_decimals=0,
                colorbar_label="Server certificate chain transferred (bytes)",
                vmin=None,
                vmax=None,
            )
            heatmap_count += int(chain_bytes_cells > 0)
            print(f"{pki}_server_chain_bytes_heatmap_cells={chain_bytes_cells}")
            pki_reconnect_rows = [
                row for row in reconnect_rows if pki_category(row) == pki
            ]
            reconnect_cells = plot_reconnect_count_heatmap(
                pki_reconnect_rows,
                out_dir / f"heatmap_reconnects_{pki}.{extension}",
                f"{run_dir.name} - {pki_title}",
            )
            heatmap_count += int(reconnect_cells > 0)
            print(f"{pki}_reconnect_count_heatmap_cells={reconnect_cells}")
        print(f"heatmaps={heatmap_count}")

    print(f"rows={len(rows)}")
    print(f"bar_chart_rows={len(plot_rows)}")
    print(f"kem_algorithm_bars={kem_bar_count}")
    print(f"signature_algorithm_bars={signature_bar_count}")
    print(f"cpu_handshake_scatter_points={cpu_scatter_count}")
    print(f"heap_handshake_scatter_points={heap_scatter_count}")
    print(f"nist_residual_bar_rows={residual_bar_count}")
    print(f"spearman_correlation_rows={correlation_count}")
    print(f"format={extension}")
    for (pki, category), category_rows in categories.items():
        print(f"{pki}_{category}={len(category_rows)}")
    print(f"out_dir={out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
