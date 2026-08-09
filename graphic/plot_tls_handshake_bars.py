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
PQC_SIG_PREFIXES = ("ML-DSA", "SLH-DSA", "LMS", "XMSS")
SECURITY_LEVELS = (1, 3, 5)
HANDSHAKE_HEATMAP_MAX_MS = 6000
HEATMAP_CMAP = LinearSegmentedColormap.from_list(
    "benchmark_green_to_red",
    ("#15803d", "#facc15", "#b91c1c"),
)
TLS_PHASES = ("tls_setup", "tls_handshake", "mqtt_connect")
TLS_DWT_METRICS = (
    ("lsu", "LSUCNT", "cycles"),
    ("cpi", "CPICNT", "cycles"),
    ("exc", "EXCCNT", "cycles"),
    ("sleep", "SLEEPCNT", "cycles"),
    ("fold", "FOLDCNT", "events"),
)
PI_PROCESS_PREFIXES = ("pi_broker", "pi_bridge")
PI_PROCESS_METRICS = (
    "utime_ticks", "stime_ticks", "minor_page_faults", "major_page_faults",
    "threads", "vmrss_kb", "vmhwm_kb", "voluntary_context_switches",
    "involuntary_context_switches", "read_bytes", "write_bytes",
    "perf_available", "perf_metrics_collected", "perf_task_clock_ms",
    "perf_cpu_clock_ms", "perf_cycles", "perf_instructions",
    "perf_cache_references", "perf_cache_misses",
    "perf_branch_instructions", "perf_branch_misses",
    "perf_stalled_cycles_frontend", "perf_stalled_cycles_backend",
    "perf_l1_dcache_loads", "perf_l1_dcache_load_misses",
    "perf_l1_icache_load_misses", "perf_dtlb_load_misses",
    "perf_itlb_load_misses", "perf_crypto_spec", "perf_simd_spec",
    "perf_context_switches", "perf_cpu_migrations", "perf_minor_faults",
    "perf_major_faults",
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
        row = {
            "case_id": attempts_csv.parent.name.split("_", 1)[-1],
            "kex_group": first.get("kex_group", ""),
            "kex_nist_level": first.get("kex_nist_level", ""),
            "cert_sig_alg": first.get("cert_sig_alg", ""),
            "sig_nist_level": first.get("sig_nist_level", ""),
            "mean_handshake_ms": f"{statistics.mean(values):.3f}",
            "stddev_raw_handshake_ms": f"{stddev:.3f}",
            "success_count": str(len(successes)),
            "mean_kem_client_total_ms": attempt_mean("kem_client_total_ms"),
            "mean_client_signature_total_ms": attempt_mean(
                "client_signature_total_ms"
            ),
            "mean_communication_overhead_ms": attempt_mean(
                "communication_overhead_ms"
            ),
            "mean_client_cpu_ms": attempt_mean("client_cpu_ms"),
            "mean_client_icache_hit_percent": attempt_mean(
                "client_icache_hit_percent"
            ),
        }
        for phase in TLS_PHASES:
            row[f"mean_{phase}_core_cycles"] = attempt_mean(
                f"{phase}_core_cycles"
            )
            for counter, _label, suffix in TLS_DWT_METRICS:
                row[f"mean_{phase}_{counter}_{suffix}"] = attempt_mean(
                    f"{phase}_{counter}_{suffix}"
                )
        for prefix in PI_PROCESS_PREFIXES:
            for metric in PI_PROCESS_METRICS:
                row[f"mean_{prefix}_{metric}"] = attempt_mean(
                    f"{prefix}_{metric}"
                )
        rows.append(row)
    return rows


def add_attempt_cpu_peaks(rows: list[dict[str, str]], run_dir: Path) -> None:
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
        if cpu_values:
            target["peak_system_cpu_usage_percent"] = (
                f"{max(cpu_values):.3f}"
            )
        if cache_values and not float_or_none(
            target.get("mean_client_icache_hit_percent")
        ):
            target["mean_client_icache_hit_percent"] = (
                f"{statistics.mean(cache_values):.3f}"
            )


def add_derived_hardware_metrics(rows: list[dict[str, str]]) -> None:
    for row in rows:
        for phase in TLS_PHASES:
            core = float_or_none(row.get(f"mean_{phase}_core_cycles"))
            if core and core > 0:
                for counter, _label, suffix in TLS_DWT_METRICS:
                    value = float_or_none(row.get(f"mean_{phase}_{counter}_{suffix}"))
                    if value is not None:
                        row[f"mean_{phase}_{counter}_per_core_percent"] = (
                            f"{100.0 * value / core:.6f}"
                        )
        for prefix in PI_PROCESS_PREFIXES:
            utime = float_or_none(row.get(f"mean_{prefix}_utime_ticks"))
            stime = float_or_none(row.get(f"mean_{prefix}_stime_ticks"))
            if utime is not None or stime is not None:
                row[f"mean_{prefix}_cpu_ticks"] = (
                    f"{(utime or 0.0) + (stime or 0.0):.3f}"
                )
            voluntary = float_or_none(
                row.get(f"mean_{prefix}_voluntary_context_switches")
            )
            involuntary = float_or_none(
                row.get(f"mean_{prefix}_involuntary_context_switches")
            )
            if voluntary is not None or involuntary is not None:
                row[f"mean_{prefix}_context_switches"] = (
                    f"{(voluntary or 0.0) + (involuntary or 0.0):.3f}"
                )
            minor = float_or_none(row.get(f"mean_{prefix}_minor_page_faults"))
            major = float_or_none(row.get(f"mean_{prefix}_major_page_faults"))
            if minor is not None or major is not None:
                row[f"mean_{prefix}_page_faults"] = (
                    f"{(minor or 0.0) + (major or 0.0):.3f}"
                )
            read_bytes = float_or_none(row.get(f"mean_{prefix}_read_bytes"))
            write_bytes = float_or_none(row.get(f"mean_{prefix}_write_bytes"))
            if read_bytes is not None or write_bytes is not None:
                row[f"mean_{prefix}_io_bytes"] = (
                    f"{(read_bytes or 0.0) + (write_bytes or 0.0):.3f}"
                )
            cycles = float_or_none(row.get(f"mean_{prefix}_perf_cycles"))
            instructions = float_or_none(
                row.get(f"mean_{prefix}_perf_instructions")
            )
            if cycles and cycles > 0 and instructions is not None:
                row[f"mean_{prefix}_perf_ipc"] = (
                    f"{instructions / cycles:.6f}"
                )
                crypto = float_or_none(row.get(f"mean_{prefix}_perf_crypto_spec"))
                simd = float_or_none(row.get(f"mean_{prefix}_perf_simd_spec"))
                if crypto is not None and instructions > 0:
                    row[f"mean_{prefix}_perf_crypto_per_kinstruction"] = (
                        f"{1000.0 * crypto / instructions:.6f}"
                    )
                if simd is not None and instructions > 0:
                    row[f"mean_{prefix}_perf_simd_per_kinstruction"] = (
                        f"{1000.0 * simd / instructions:.6f}"
                    )
            cache_refs = float_or_none(
                row.get(f"mean_{prefix}_perf_cache_references")
            )
            cache_misses = float_or_none(
                row.get(f"mean_{prefix}_perf_cache_misses")
            )
            if cache_refs and cache_refs > 0 and cache_misses is not None:
                row[f"mean_{prefix}_perf_cache_miss_percent"] = (
                    f"{100.0 * cache_misses / cache_refs:.6f}"
                )
            branches = float_or_none(
                row.get(f"mean_{prefix}_perf_branch_instructions")
            )
            branch_misses = float_or_none(
                row.get(f"mean_{prefix}_perf_branch_misses")
            )
            if branches and branches > 0 and branch_misses is not None:
                row[f"mean_{prefix}_perf_branch_miss_percent"] = (
                    f"{100.0 * branch_misses / branches:.6f}"
                )
            l1_loads = float_or_none(
                row.get(f"mean_{prefix}_perf_l1_dcache_loads")
            )
            l1_misses = float_or_none(
                row.get(f"mean_{prefix}_perf_l1_dcache_load_misses")
            )
            if l1_loads and l1_loads > 0 and l1_misses is not None:
                row[f"mean_{prefix}_perf_l1_dcache_load_miss_percent"] = (
                    f"{100.0 * l1_misses / l1_loads:.6f}"
                )
            frontend = float_or_none(
                row.get(f"mean_{prefix}_perf_stalled_cycles_frontend")
            )
            backend = float_or_none(
                row.get(f"mean_{prefix}_perf_stalled_cycles_backend")
            )
            if cycles and cycles > 0:
                if frontend is not None:
                    row[f"mean_{prefix}_perf_frontend_stall_percent"] = (
                        f"{100.0 * frontend / cycles:.6f}"
                    )
                if backend is not None:
                    row[f"mean_{prefix}_perf_backend_stall_percent"] = (
                        f"{100.0 * backend / cycles:.6f}"
                    )


def load_rows(run_dir: Path) -> list[dict[str, str]]:
    rows = load_from_summary(run_dir / "summary.csv")
    if rows:
        add_attempt_cpu_peaks(rows, run_dir)
        add_derived_hardware_metrics(rows)
        return rows
    rows = load_from_attempts(run_dir)
    add_attempt_cpu_peaks(rows, run_dir)
    add_derived_hardware_metrics(rows)
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
    sig = row.get("cert_sig_alg", "")
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
        algorithm = row.get(algorithm_field, "")
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
    kem_levels = {
        row.get("kex_group", ""): kem_security_level(row) for row in rows
    }
    sig_levels = {
        row.get("cert_sig_alg", ""): signature_security_level(row)
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
    kem_levels = {
        row.get("kex_group", ""): kem_security_level(row) for row in rows
    }
    sig_levels = {
        row.get("cert_sig_alg", ""): signature_security_level(row)
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
                    ha="center", va="center", fontsize=12,
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

    kem_bar_count = plot_algorithm_metric(
        plot_rows,
        algorithm_field="kex_group",
        level_field="kex_nist_level",
        metric_field="mean_kem_client_total_ms",
        title=f"Client KEM execution time - {run_dir.name}",
        ylabel="Mean client KEM time (ms)",
        color="#2a9d8f",
        output=out_dir / f"kem_execution_time.{extension}",
    )
    signature_bar_count = plot_algorithm_metric(
        plot_rows,
        algorithm_field="cert_sig_alg",
        level_field="sig_nist_level",
        metric_field="mean_client_signature_total_ms",
        title=f"Client digital-signature execution time - {run_dir.name}",
        ylabel="Mean client signature time (ms)",
        color="#e9c46a",
        output=out_dir / f"signature_execution_time.{extension}",
    )

    if args.heatmap:
        heatmap_count = 0
        plot_heatmap(
            rows,
            out_dir / f"tls_handshake_heatmap.{extension}",
            run_dir.name,
        )
        heatmap_count += 1
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
            if plotted:
                heatmap_count += 1
        cache_cells = plot_percent_heatmap(
            rows,
            "mean_client_icache_hit_percent",
            f"Client instruction-cache hit rate - {run_dir.name}",
            out_dir / f"heatmap_client_icache_hit_percent.{extension}",
            colorbar_label="Mean instruction-cache hit rate (%)",
        )
        print(f"mean_client_icache_hit_percent_heatmap_cells={cache_cells}")
        if cache_cells:
            heatmap_count += 1
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
        if heap_bytes_cells:
            heatmap_count += 1
        for phase in TLS_PHASES:
            phase_label = phase.replace("_", " ")
            for counter, label, _suffix in TLS_DWT_METRICS:
                metric = f"mean_{phase}_{counter}_per_core_percent"
                cells = plot_percent_heatmap(
                    rows,
                    metric,
                    f"Board {phase_label} {label} / CYCCNT - {run_dir.name}",
                    out_dir / f"heatmap_{phase}_{counter}_per_core_percent.{extension}",
                    value_suffix="%",
                    value_decimals=3,
                    colorbar_label=f"{label} / CYCCNT (%)",
                    vmin=0,
                    vmax=None,
                )
                print(f"{metric}_heatmap_cells={cells}")
                if cells:
                    heatmap_count += 1
        pi_heatmaps = (
            ("cpu_ticks", "CPU ticks", "Mean user + system CPU ticks"),
            ("context_switches", "context switches", "Mean context switches"),
            ("page_faults", "page faults", "Mean page faults"),
            ("vmhwm_kb", "high-water RSS", "Mean VmHWM (KB)"),
            ("io_bytes", "I/O bytes", "Mean read + write bytes"),
            ("perf_task_clock_ms", "perf task-clock", "Mean task-clock (ms)"),
            ("perf_cycles", "perf cycles", "Mean user-space CPU cycles"),
            (
                "perf_instructions", "perf instructions",
                "Mean user-space retired instructions",
            ),
            ("perf_ipc", "perf IPC", "Instructions per cycle"),
            (
                "perf_cache_miss_percent", "perf cache miss rate",
                "Cache misses / references (%)",
            ),
            (
                "perf_branch_miss_percent", "perf branch miss rate",
                "Branch misses / branch instructions (%)",
            ),
            (
                "perf_frontend_stall_percent", "perf frontend stalls",
                "Frontend stalled cycles / cycles (%)",
            ),
            (
                "perf_backend_stall_percent", "perf backend stalls",
                "Backend stalled cycles / cycles (%)",
            ),
            (
                "perf_l1_dcache_load_miss_percent",
                "perf L1D load miss rate",
                "L1D load misses / loads (%)",
            ),
            (
                "perf_crypto_spec", "perf crypto instructions",
                "Arm PMU CRYPTO_SPEC events",
            ),
            (
                "perf_crypto_per_kinstruction",
                "perf crypto instruction density",
                "CRYPTO_SPEC events per 1000 instructions",
            ),
            (
                "perf_simd_spec", "perf SIMD instructions",
                "Arm PMU ASE_SPEC events",
            ),
            (
                "perf_simd_per_kinstruction",
                "perf SIMD instruction density",
                "ASE_SPEC events per 1000 instructions",
            ),
        )
        for prefix in PI_PROCESS_PREFIXES:
            process_label = "broker" if prefix == "pi_broker" else "BLE bridge"
            for metric, title, colorbar_label in pi_heatmaps:
                field = f"mean_{prefix}_{metric}"
                is_percent = metric.endswith("_percent")
                decimals = 3 if (
                    is_percent
                    or metric == "perf_ipc"
                    or metric.endswith("_per_kinstruction")
                ) else 0
                cells = plot_percent_heatmap(
                    rows,
                    field,
                    f"Raspberry Pi {process_label} {title} - {run_dir.name}",
                    out_dir / f"heatmap_{prefix}_{metric}.{extension}",
                    value_suffix="%" if is_percent else "",
                    value_decimals=decimals,
                    colorbar_label=colorbar_label,
                    vmin=None,
                    vmax=None,
                )
                print(f"{field}_heatmap_cells={cells}")
                if cells:
                    heatmap_count += 1
        reconnect_rows = load_reconnect_count_rows(run_dir)
        reconnect_cells = plot_reconnect_count_heatmap(
            reconnect_rows,
            out_dir / f"heatmap_reconnects.{extension}",
            run_dir.name,
        )
        print(f"reconnect_count_heatmap_cells={reconnect_cells}")
        if reconnect_cells:
            heatmap_count += 1
        print(f"heatmaps={heatmap_count}")

    print(f"rows={len(rows)}")
    print(f"bar_chart_rows={len(plot_rows)}")
    print(f"kem_algorithm_bars={kem_bar_count}")
    print(f"signature_algorithm_bars={signature_bar_count}")
    print(f"format={extension}")
    for category, category_rows in categories.items():
        print(f"{category}={len(category_rows)}")
    print(f"out_dir={out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
