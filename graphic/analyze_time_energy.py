#!/usr/bin/env python3
"""Analyze per-attempt benchmark timing, energy, and communication metrics."""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import warnings
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Sequence

try:
    import matplotlib.pyplot as plt
    import numpy as np
    import pandas as pd
    import seaborn as sns
    import statsmodels.api as sm
    import statsmodels.formula.api as smf
    from scipy import stats
    from statsmodels.stats.multitest import multipletests
except ImportError as exc:  # pragma: no cover - exercised from the CLI
    raise SystemExit(
        "Missing statistical dependencies. Install them with:\n"
        "  python3 -m pip install -r benchmarking/requirements.txt\n"
        f"Original error: {exc}"
    ) from exc


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RESULTS_ROOT = PROJECT_ROOT / "benchmarking" / "results"
DEFAULT_BOOTSTRAP_ITERATIONS = 5000

BASE_REQUIRED = (
    "raw_handshake_ms",
    "handshake_duration_ms",
    "handshake_energy_uj",
)
NUMERIC_COLUMNS = (
    "session",
    "attempt_index",
    "schedule_index",
    "reconnect_count",
    "raw_handshake_ms",
    "end_to_end_ms",
    "communication_overhead_ms",
    "kem_client_total_ms",
    "kem_keygen_ms",
    "kem_decapsulation_ms",
    "classical_kex_keygen_ms",
    "classical_kex_shared_secret_ms",
    "client_signature_total_ms",
    "x509_chain_signature_verify_ms",
    "tls_certificate_verify_signature_verify_ms",
    "mtls_signature_generate_ms",
    "kex_nist_level",
    "sig_nist_level",
    "kex_public_key_bytes",
    "kex_ciphertext_bytes",
    "sig_signature_bytes",
    "l2cap_tx_bytes",
    "l2cap_rx_bytes",
    "client_cpu_ms",
    "client_heap_peak_bytes",
    "server_chain_bytes",
    "client_kem_duration_ms",
    "client_kem_energy_uj",
    "client_kem_avg_current_ua",
    "client_signature_duration_ms",
    "client_signature_energy_uj",
    "client_signature_avg_current_ua",
    "handshake_duration_ms",
    "handshake_energy_uj",
    "handshake_avg_current_ua",
    "total_execution_duration_ms",
    "total_execution_energy_uj",
    "total_execution_avg_current_ua",
    "power_profiler_vdd_mv",
)

CORRELATION_SPECS = (
    ("handshake_time_energy", "raw_handshake_ms", "handshake_energy_uj"),
    ("kem_time_energy", "kem_time_ms", "client_kem_energy_uj"),
    (
        "signature_time_energy",
        "signature_time_ms",
        "client_signature_energy_uj",
    ),
    (
        "total_time_energy",
        "end_to_end_ms",
        "total_execution_energy_uj",
    ),
    (
        "signature_size_communication",
        "sig_signature_bytes",
        "communication_overhead_ms",
    ),
)


@dataclass
class ModelFit:
    name: str
    status: str
    result: object | None
    formula: str
    message: str = ""


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "run_dirs",
        nargs="+",
        help=(
            "One or more benchmark result directories or run IDs under "
            "benchmarking/results."
        ),
    )
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--seed", type=int, default=123)
    parser.add_argument(
        "--bootstrap-iterations",
        type=int,
        default=DEFAULT_BOOTSTRAP_ITERATIONS,
    )
    parser.add_argument(
        "--include-reconnects",
        action="store_true",
        help="Include successful attempts that required a reconnect.",
    )
    parser.add_argument(
        "--generate-png",
        action="store_true",
        help="Generate PNG figures instead of vector PDF.",
    )
    args = parser.parse_args(argv)
    if args.bootstrap_iterations < 0:
        parser.error("--bootstrap-iterations must be non-negative")
    return args


def resolve_run_dir(value: str | Path) -> Path:
    path = Path(value).expanduser()
    if path.is_dir():
        return path.resolve()
    candidate = RESULTS_ROOT / path
    if candidate.is_dir():
        return candidate.resolve()
    raise FileNotFoundError(f"Benchmark result directory not found: {value}")


def case_id_from_directory(path: Path) -> str:
    return re.sub(r"^\d+_", "", path.parent.name)


def numeric(series: pd.Series) -> pd.Series:
    return pd.to_numeric(series, errors="coerce")


def row_sum(frame: pd.DataFrame, fields: Sequence[str]) -> pd.Series:
    available = [field for field in fields if field in frame]
    if not available:
        return pd.Series(np.nan, index=frame.index, dtype=float)
    values = frame[available].apply(pd.to_numeric, errors="coerce")
    total = values.fillna(0.0).sum(axis=1)
    return total.where(values.notna().any(axis=1))


def algorithm_category(kex_group: str, signature: str) -> str:
    kex = str(kex_group).upper().replace("-", "")
    sig = str(signature).upper().replace("-", "")
    kex_has_pqc = "MLKEM" in kex
    kex_has_classic = any(token in kex for token in ("ECDHE", "SECP", "X25519"))
    sig_has_pqc = any(token in sig for token in ("MLDSA", "SLHDSA", "XMSS", "LMS"))
    sig_has_classic = any(token in sig for token in ("ECDSA", "RSAPSS"))
    has_pqc = kex_has_pqc or sig_has_pqc
    has_classic = kex_has_classic or sig_has_classic
    if has_pqc and has_classic:
        return "mixed"
    return "pqc_only" if has_pqc else "classic_only"


def _read_attempts(path: Path, run_id: str) -> pd.DataFrame:
    frame = pd.read_csv(path, dtype=str, keep_default_na=False)
    frame["run_id"] = run_id
    frame["case_id"] = case_id_from_directory(path)
    frame["source_file"] = str(path.resolve())
    return frame


def load_attempt_data(
    run_dirs: Sequence[Path],
    *,
    include_reconnects: bool,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    frames: list[pd.DataFrame] = []
    status_counts: Counter[tuple[str, str, str]] = Counter()
    rejection_counts: Counter[tuple[str, str, str]] = Counter()

    for run_dir in run_dirs:
        attempts = sorted((run_dir / "cases").glob("*/attempts.csv"))
        if not attempts:
            rejection_counts[
                (run_dir.name, "", "missing_attempts_csv")
            ] += 1
            continue
        for path in attempts:
            frame = _read_attempts(path, run_dir.name)
            case_id = case_id_from_directory(path)
            for status, count in frame.get(
                "status", pd.Series("", index=frame.index)
            ).value_counts().items():
                status_counts[
                    (run_dir.name, case_id, f"status_{status or 'missing'}")
                ] += int(count)
            frames.append(frame)

    if not frames:
        quality = pd.DataFrame(
            [
                {
                    "run_id": run,
                    "case_id": case,
                    "reason": reason,
                    "count": count,
                }
                for (run, case, reason), count in rejection_counts.items()
            ]
        )
        return pd.DataFrame(), quality

    data = pd.concat(frames, ignore_index=True, sort=False)
    keep = pd.Series(True, index=data.index)

    def reject(mask: pd.Series, reason: str) -> None:
        newly_rejected = keep & mask.fillna(False)
        groups = data.loc[newly_rejected].groupby(
            ["run_id", "case_id"]
        ).size()
        for (run_id, case_id), count in groups.items():
            rejection_counts[(str(run_id), str(case_id), reason)] += int(count)
        keep.loc[newly_rejected] = False

    reject(data.get("status", "") != "success", "not_success")
    reject(data.get("warmup", "0").astype(str) == "1", "warmup")
    reject(data.get("power_status", "") != "success", "power_incomplete")

    reconnects = numeric(data.get("reconnect_count", pd.Series(0, index=data.index))).fillna(0)
    if not include_reconnects:
        reject(reconnects > 0, "reconnected")

    for field in BASE_REQUIRED:
        if field not in data:
            reject(pd.Series(True, index=data.index), f"missing_{field}")
            continue
        values = numeric(data[field])
        reject(values.isna(), f"missing_{field}")
        reject(values <= 0, f"nonpositive_{field}")

    data = data.loc[keep].copy()
    for field in NUMERIC_COLUMNS:
        if field in data:
            data[field] = numeric(data[field])
        else:
            data[field] = np.nan

    data["kem_time_ms"] = data["kem_client_total_ms"].where(
        data["kem_client_total_ms"].notna(),
        row_sum(
            data,
            (
                "kem_keygen_ms",
                "kem_decapsulation_ms",
                "classical_kex_keygen_ms",
                "classical_kex_shared_secret_ms",
            ),
        ),
    )
    data["signature_time_ms"] = data["client_signature_total_ms"].where(
        data["client_signature_total_ms"].notna(),
        row_sum(
            data,
            (
                "x509_chain_signature_verify_ms",
                "tls_certificate_verify_signature_verify_ms",
                "mtls_signature_generate_ms",
            ),
        ),
    )
    data["transmitted_bytes"] = data["l2cap_tx_bytes"]
    data["total_l2cap_bytes"] = data["l2cap_tx_bytes"] + data["l2cap_rx_bytes"]
    data["case_cluster_id"] = (
        data["run_id"].astype(str) + "::" + data["case_id"].astype(str)
    )
    session_text = data["session"].fillna(-1).astype(int).astype(str)
    data["session_id"] = (
        data["run_id"].astype(str)
        + "::"
        + data["case_id"].astype(str)
        + "::"
        + session_text
    )
    categorical_defaults = {
        "kex_group": "unknown_kem",
        "pki_chain_id": "",
        "pki_kind": "legacy_homogeneous",
        "root_sig_alg": "",
        "leaf_sig_alg": "",
        "cert_sig_alg": "unknown_signature",
    }
    for field, default in categorical_defaults.items():
        if field not in data:
            data[field] = default
        data[field] = data[field].fillna("").astype(str)
        data.loc[data[field].str.strip() == "", field] = default
    data.loc[data["pki_chain_id"] == "", "pki_chain_id"] = data["cert_sig_alg"]
    data.loc[data["root_sig_alg"] == "", "root_sig_alg"] = data["cert_sig_alg"]
    data.loc[data["leaf_sig_alg"] == "", "leaf_sig_alg"] = data["cert_sig_alg"]
    missing_text = pd.Series("", index=data.index, dtype=str)
    data["algorithm_category"] = [
        algorithm_category(kex, sig)
        for kex, sig in zip(
            data.get("kex_group", missing_text),
            data.get("cert_sig_alg", missing_text),
            strict=False,
        )
    ]

    add_power_and_edp_metrics(data)
    quality_rows = [
        {
            "run_id": run,
            "case_id": case,
            "reason": reason,
            "count": count,
        }
        for (run, case, reason), count in sorted(
            {**status_counts, **rejection_counts}.items()
        )
    ]
    for (run_id, case_id), count in data.groupby(
        ["run_id", "case_id"]
    ).size().items():
        quality_rows.append(
            {
                "run_id": run_id,
                "case_id": case_id,
                "reason": "accepted_attempts",
                "count": int(count),
            }
        )
    quality_rows.append(
        {
            "run_id": "ALL",
            "case_id": "ALL",
            "reason": "accepted_attempts",
            "count": len(data),
        }
    )
    return data, pd.DataFrame(quality_rows)


def add_power_and_edp_metrics(data: pd.DataFrame) -> None:
    windows = (
        ("handshake", "raw_handshake_ms"),
        ("client_kem", "kem_time_ms"),
        ("client_signature", "signature_time_ms"),
        ("total_execution", "end_to_end_ms"),
    )
    voltage = data["power_profiler_vdd_mv"]
    for window, performance_time in windows:
        energy = data[f"{window}_energy_uj"]
        duration = data[f"{window}_duration_ms"]
        current = data[f"{window}_avg_current_ua"]
        data[f"{window}_power_mw"] = energy / duration
        data[f"{window}_current_power_mw"] = voltage * current / 1_000_000.0
        data[f"{window}_power_relative_error"] = (
            data[f"{window}_power_mw"] - data[f"{window}_current_power_mw"]
        ).abs() / data[f"{window}_power_mw"].replace(0, np.nan)
        data[f"{window}_edp_mj_s"] = (
            energy / 1000.0
        ) * (data[performance_time] / 1000.0)


def safe_correlation(
    x: pd.Series,
    y: pd.Series,
    method: str,
) -> tuple[float, float, int, str]:
    pair = pd.concat([x, y], axis=1).dropna()
    if len(pair) < 3:
        return math.nan, math.nan, len(pair), "insufficient_data"
    if pair.iloc[:, 0].nunique() < 2 or pair.iloc[:, 1].nunique() < 2:
        return math.nan, math.nan, len(pair), "constant_variable"
    function = stats.pearsonr if method == "pearson" else stats.spearmanr
    result = function(pair.iloc[:, 0], pair.iloc[:, 1])
    return float(result.statistic), float(result.pvalue), len(pair), "ok"


def cluster_bootstrap_ci(
    frame: pd.DataFrame,
    statistic: Callable[[pd.DataFrame], float],
    *,
    iterations: int,
    rng: np.random.Generator,
    cluster_column: str = "session_id",
) -> tuple[float, float, int]:
    if iterations == 0 or frame.empty:
        return math.nan, math.nan, 0
    if cluster_column not in frame:
        return math.nan, math.nan, 0
    grouped = frame.groupby(cluster_column, sort=False, observed=True).indices
    clusters = np.asarray(list(grouped), dtype=object)
    if len(clusters) < 2:
        return math.nan, math.nan, 0
    values: list[float] = []
    for _ in range(iterations):
        selected = rng.choice(clusters, size=len(clusters), replace=True)
        positions = np.concatenate([grouped[cluster] for cluster in selected])
        labels = np.concatenate(
            [
                np.full(len(grouped[cluster]), draw_index, dtype=int)
                for draw_index, cluster in enumerate(selected)
            ]
        )
        sample = frame.iloc[positions].copy()
        sample["__bootstrap_cluster"] = labels
        value = statistic(sample)
        if math.isfinite(value):
            values.append(value)
    if len(values) < max(20, iterations // 10):
        return math.nan, math.nan, len(values)
    low, high = np.percentile(values, [2.5, 97.5])
    return float(low), float(high), len(values)


def _bootstrap_interval(values: np.ndarray, iterations: int) -> tuple[float, float, int]:
    clean = np.asarray(values, dtype=float)
    clean = clean[np.isfinite(clean)]
    if len(clean) < max(20, iterations // 10):
        return math.nan, math.nan, len(clean)
    low, high = np.percentile(clean, [2.5, 97.5])
    return float(low), float(high), len(clean)


def fast_cluster_correlation_ci(
    frame: pd.DataFrame,
    x_name: str,
    y_name: str,
    method: str,
    level: str,
    *,
    iterations: int,
    rng: np.random.Generator,
    cluster_column: str,
) -> tuple[float, float, int]:
    """Bootstrap a correlation from per-cluster sufficient statistics."""
    if iterations == 0 or frame.empty or cluster_column not in frame:
        return math.nan, math.nan, 0
    subset = frame[[cluster_column, x_name, y_name]].dropna().copy()
    grouped = subset.groupby(cluster_column, sort=False, observed=True).indices
    if len(grouped) < 2:
        return math.nan, math.nan, 0

    if level == "between_case":
        values = subset.groupby(cluster_column, sort=False, observed=True)[
            [x_name, y_name]
        ].mean()
        x = values[x_name].to_numpy(dtype=float)
        y = values[y_name].to_numpy(dtype=float)
        if method == "spearman":
            x = stats.rankdata(x)
            y = stats.rankdata(y)
        statistics = np.column_stack(
            [np.ones(len(x)), x, y, x * x, y * y, x * y]
        )
    else:
        x = subset[x_name].to_numpy(dtype=float)
        y = subset[y_name].to_numpy(dtype=float)
        if method == "spearman" and level == "pooled":
            x = stats.rankdata(x)
            y = stats.rankdata(y)
        group_statistics = []
        for positions in grouped.values():
            group_x = x[positions].copy()
            group_y = y[positions].copy()
            if level == "within_case":
                if method == "spearman":
                    group_x = stats.rankdata(group_x)
                    group_y = stats.rankdata(group_y)
                group_x -= group_x.mean()
                group_y -= group_y.mean()
            group_statistics.append(
                [
                    len(group_x),
                    group_x.sum(),
                    group_y.sum(),
                    np.dot(group_x, group_x),
                    np.dot(group_y, group_y),
                    np.dot(group_x, group_y),
                ]
            )
        statistics = np.asarray(group_statistics, dtype=float)

    cluster_count = len(statistics)
    counts = rng.multinomial(
        cluster_count,
        np.full(cluster_count, 1.0 / cluster_count),
        size=iterations,
    )
    totals = counts @ statistics
    n, sum_x, sum_y, sum_xx, sum_yy, sum_xy = totals.T
    covariance = sum_xy - sum_x * sum_y / n
    variance_x = sum_xx - np.square(sum_x) / n
    variance_y = sum_yy - np.square(sum_y) / n
    with np.errstate(divide="ignore", invalid="ignore"):
        coefficients = covariance / np.sqrt(variance_x * variance_y)
    return _bootstrap_interval(coefficients, iterations)


def fast_cluster_partial_ci(
    frame: pd.DataFrame,
    x_name: str,
    y_name: str,
    controls: Sequence[str],
    method: str,
    *,
    iterations: int,
    rng: np.random.Generator,
    cluster_column: str,
) -> tuple[float, float, int]:
    """Bootstrap partial correlation from weighted cluster cross-products."""
    if iterations == 0 or frame.empty or cluster_column not in frame:
        return math.nan, math.nan, 0
    fields = [cluster_column, "run_id", x_name, y_name, *controls]
    subset = frame[fields].dropna().copy()
    matrix = subset[[x_name, y_name, *controls]].astype(float)
    if method == "spearman":
        matrix = matrix.rank(method="average")
    if subset["run_id"].nunique() > 1:
        run_dummies = pd.get_dummies(
            subset["run_id"], prefix="run", drop_first=True, dtype=float
        )
        matrix = pd.concat([matrix, run_dummies], axis=1)
    values = matrix.to_numpy(dtype=float)
    grouped = subset.groupby(cluster_column, sort=False, observed=True).indices
    if len(grouped) < 2:
        return math.nan, math.nan, 0
    counts_per_cluster = []
    sums = []
    cross_products = []
    for positions in grouped.values():
        chunk = values[positions]
        counts_per_cluster.append(len(chunk))
        sums.append(chunk.sum(axis=0))
        cross_products.append(chunk.T @ chunk)
    cluster_count = len(grouped)
    weights = rng.multinomial(
        cluster_count,
        np.full(cluster_count, 1.0 / cluster_count),
        size=iterations,
    )
    total_n = weights @ np.asarray(counts_per_cluster, dtype=float)
    total_sum = weights @ np.asarray(sums, dtype=float)
    total_cross = np.einsum(
        "ic,cjk->ijk", weights, np.asarray(cross_products, dtype=float)
    )
    centered = total_cross - np.einsum(
        "ij,ik->ijk", total_sum, total_sum
    ) / total_n[:, None, None]
    try:
        precision = np.linalg.pinv(centered)
    except np.linalg.LinAlgError:
        return math.nan, math.nan, 0
    with np.errstate(divide="ignore", invalid="ignore"):
        coefficients = -precision[:, 0, 1] / np.sqrt(
            precision[:, 0, 0] * precision[:, 1, 1]
        )
    return _bootstrap_interval(coefficients, iterations)


def correlation_table(
    data: pd.DataFrame,
    *,
    bootstrap_iterations: int,
    seed: int,
) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    rng = np.random.default_rng(seed)
    for analysis, x_name, y_name in CORRELATION_SPECS:
        subset = data.dropna(subset=[x_name, y_name, "session_id"])
        for method in ("pearson", "spearman"):
            coefficient, p_value, n, status = safe_correlation(
                subset[x_name], subset[y_name], method
            )

            ci_low, ci_high, valid = fast_cluster_correlation_ci(
                subset,
                x_name,
                y_name,
                method,
                "pooled",
                iterations=bootstrap_iterations,
                rng=rng,
                cluster_column="session_id",
            )
            rows.append(
                {
                    "analysis": analysis,
                    "method": method,
                    "x": x_name,
                    "y": y_name,
                    "n": n,
                    "coefficient": coefficient,
                    "p_value": p_value,
                    "ci95_low": ci_low,
                    "ci95_high": ci_high,
                    "bootstrap_valid": valid,
                    "status": status,
                }
            )
    return pd.DataFrame(rows)


def _correlation_at_level(
    frame: pd.DataFrame,
    x_name: str,
    y_name: str,
    method: str,
    level: str,
) -> tuple[float, float, int, str]:
    """Calculate pooled, between-case, or within-case association."""
    subset = frame.dropna(subset=[x_name, y_name]).copy()
    if level == "pooled":
        return safe_correlation(subset[x_name], subset[y_name], method)

    group_column = (
        "__bootstrap_cluster"
        if "__bootstrap_cluster" in subset
        else "case_cluster_id"
    )
    if group_column not in subset:
        return math.nan, math.nan, 0, "missing_case_cluster"
    if level == "between_case":
        means = subset.groupby(group_column, observed=True)[[x_name, y_name]].mean()
        return safe_correlation(means[x_name], means[y_name], method)
    if level != "within_case":
        raise ValueError(f"Unknown correlation level: {level}")

    values = subset[[group_column, x_name, y_name]].copy()
    if method == "spearman":
        values[x_name] = values.groupby(group_column, observed=True)[x_name].rank(
            method="average", pct=True
        )
        values[y_name] = values.groupby(group_column, observed=True)[y_name].rank(
            method="average", pct=True
        )
    values[x_name] -= values.groupby(group_column, observed=True)[x_name].transform(
        "mean"
    )
    values[y_name] -= values.groupby(group_column, observed=True)[y_name].transform(
        "mean"
    )
    return safe_correlation(values[x_name], values[y_name], "pearson")


def between_within_correlation_table(
    data: pd.DataFrame,
    *,
    bootstrap_iterations: int,
    seed: int,
) -> pd.DataFrame:
    """Decompose associations into pooled, case-mean, and case-centered parts."""
    rows: list[dict[str, object]] = []
    rng = np.random.default_rng(seed + 10)
    for analysis, x_name, y_name in CORRELATION_SPECS:
        subset = data.dropna(
            subset=[x_name, y_name, "case_cluster_id"]
        ).copy()
        for method in ("pearson", "spearman"):
            for level in ("pooled", "between_case", "within_case"):
                coefficient, p_value, n, status = _correlation_at_level(
                    subset, x_name, y_name, method, level
                )

                ci_low, ci_high, valid = fast_cluster_correlation_ci(
                    subset,
                    x_name,
                    y_name,
                    method,
                    level,
                    iterations=bootstrap_iterations,
                    rng=rng,
                    cluster_column="case_cluster_id",
                )
                rows.append(
                    {
                        "analysis": analysis,
                        "level": level,
                        "method": method,
                        "x": x_name,
                        "y": y_name,
                        "n": n,
                        "case_count": subset["case_cluster_id"].nunique(),
                        "coefficient": coefficient,
                        "p_value": p_value,
                        "ci95_low": ci_low,
                        "ci95_high": ci_high,
                        "bootstrap_valid": valid,
                        "status": status,
                    }
                )
    return pd.DataFrame(rows)


def residualize(
    frame: pd.DataFrame,
    target: str,
    controls: Sequence[str],
) -> pd.Series:
    design = frame[list(controls)].copy()
    if frame["run_id"].nunique() > 1:
        design = pd.concat(
            [
                design,
                pd.get_dummies(
                    frame["run_id"], prefix="run", drop_first=True, dtype=float
                ),
            ],
            axis=1,
        )
    design = sm.add_constant(design.astype(float), has_constant="add")
    result = sm.OLS(frame[target].astype(float), design).fit()
    return pd.Series(result.resid, index=frame.index)


def partial_coefficient(
    frame: pd.DataFrame,
    x_name: str,
    y_name: str,
    controls: Sequence[str],
    method: str = "pearson",
) -> tuple[float, float, int, str]:
    fields = [x_name, y_name, *controls, "run_id"]
    subset = frame[fields].dropna().copy()
    if len(subset) <= len(controls) + 2:
        return math.nan, math.nan, len(subset), "insufficient_data"
    if method not in {"pearson", "spearman"}:
        raise ValueError(f"Unknown partial-correlation method: {method}")
    if method == "spearman":
        for field in (x_name, y_name, *controls):
            subset[field] = subset[field].rank(method="average")
    try:
        x_residual = residualize(subset, x_name, controls)
        y_residual = residualize(subset, y_name, controls)
    except (ValueError, np.linalg.LinAlgError):
        return math.nan, math.nan, len(subset), "singular_controls"
    return safe_correlation(x_residual, y_residual, "pearson")


def partial_correlation_table(
    data: pd.DataFrame,
    *,
    bootstrap_iterations: int,
    seed: int,
) -> tuple[pd.DataFrame, dict[str, tuple[pd.Series, pd.Series]]]:
    specs = (
        (
            "signature_total_energy",
            "signature_time_ms",
            "handshake_energy_uj",
            ("kem_time_ms", "communication_overhead_ms"),
        ),
        (
            "signature_window_energy",
            "signature_time_ms",
            "client_signature_energy_uj",
            ("kem_time_ms", "communication_overhead_ms"),
        ),
        (
            "kem_total_energy",
            "kem_time_ms",
            "handshake_energy_uj",
            ("signature_time_ms", "communication_overhead_ms"),
        ),
        (
            "kem_window_energy",
            "kem_time_ms",
            "client_kem_energy_uj",
            ("signature_time_ms", "communication_overhead_ms"),
        ),
        (
            "signature_handshake_time",
            "signature_time_ms",
            "raw_handshake_ms",
            ("kem_time_ms", "communication_overhead_ms"),
        ),
        (
            "kem_handshake_time",
            "kem_time_ms",
            "raw_handshake_ms",
            ("signature_time_ms", "communication_overhead_ms"),
        ),
        (
            "communication_handshake_time",
            "communication_overhead_ms",
            "raw_handshake_ms",
            ("kem_time_ms", "signature_time_ms"),
        ),
    )
    rows: list[dict[str, object]] = []
    residuals: dict[str, tuple[pd.Series, pd.Series]] = {}
    rng = np.random.default_rng(seed + 1)
    for name, x_name, y_name, controls in specs:
        fields = [
            x_name,
            y_name,
            *controls,
            "run_id",
            "session_id",
            "case_cluster_id",
        ]
        subset = data[fields].dropna().copy()
        for method in ("pearson", "spearman"):
            coefficient, p_value, n, status = partial_coefficient(
                subset, x_name, y_name, controls, method=method
            )

            ci_low, ci_high, valid = fast_cluster_partial_ci(
                subset,
                x_name,
                y_name,
                controls,
                method,
                iterations=bootstrap_iterations,
                rng=rng,
                cluster_column="case_cluster_id",
            )
            if method == "pearson" and status == "ok":
                residuals[name] = (
                    residualize(subset, x_name, controls),
                    residualize(subset, y_name, controls),
                )
            rows.append(
                {
                    "analysis": name,
                    "method": method,
                    "x": x_name,
                    "y": y_name,
                    "controls": ";".join(controls),
                    "n": n,
                    "case_count": subset["case_cluster_id"].nunique(),
                    "coefficient": coefficient,
                    "p_value": p_value,
                    "ci95_low": ci_low,
                    "ci95_high": ci_high,
                    "bootstrap_valid": valid,
                    "status": status,
                }
            )
    return pd.DataFrame(rows), residuals


def zscore(series: pd.Series) -> pd.Series:
    standard_deviation = series.std(ddof=0)
    if not math.isfinite(standard_deviation) or standard_deviation == 0:
        return pd.Series(np.nan, index=series.index)
    return (series - series.mean()) / standard_deviation


def fit_mixed_model(
    data: pd.DataFrame,
    *,
    name: str,
    response: str,
    predictors: Sequence[str],
    standardized: bool = False,
) -> tuple[ModelFit, pd.DataFrame]:
    group_field = "case_cluster_id" if "case_cluster_id" in data else "case_id"
    fields = [
        response,
        *predictors,
        "run_id",
        "case_id",
        group_field,
        "session_id",
    ]
    fields = list(dict.fromkeys(fields))
    frame = data[fields].dropna().copy()
    if len(frame) < max(12, len(predictors) + 6):
        fit = ModelFit(name, "insufficient_data", None, "", "too few rows")
        return fit, pd.DataFrame()
    if frame[group_field].nunique() < 2 or frame["session_id"].nunique() < 2:
        fit = ModelFit(
            name, "insufficient_data", None, "", "too few cases or sessions"
        )
        return fit, pd.DataFrame()

    response_name = response
    predictor_names = list(predictors)
    if standardized:
        response_name = f"z_{response}"
        frame[response_name] = zscore(frame[response])
        predictor_names = []
        for predictor in predictors:
            name_z = f"z_{predictor}"
            frame[name_z] = zscore(frame[predictor])
            predictor_names.append(name_z)
        if frame[[response_name, *predictor_names]].isna().any().any():
            fit = ModelFit(
                name, "constant_variable", None, "", "cannot standardize"
            )
            return fit, pd.DataFrame()

    terms = [*predictor_names]
    if frame["run_id"].nunique() > 1:
        terms.append("C(run_id)")
    formula = f"{response_name} ~ " + " + ".join(terms)
    try:
        model = smf.mixedlm(
            formula,
            frame,
            groups=frame[group_field],
            re_formula="1",
            vc_formula={"session": "0 + C(session_id)"},
        )
    except Exception as exc:
        return ModelFit(name, "model_error", None, formula, str(exc)), pd.DataFrame()

    result = None
    messages: list[str] = []
    for method in ("lbfgs", "powell"):
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                candidate = model.fit(method=method, reml=False, maxiter=2000)
            messages.extend(str(item.message) for item in caught)
            result = candidate
            if bool(candidate.converged):
                break
        except Exception as exc:
            messages.append(f"{method}: {exc}")

    if result is None:
        return ModelFit(
            name, "model_error", None, formula, " | ".join(messages)
        ), pd.DataFrame()

    status = "ok" if bool(result.converged) else "not_converged"
    confidence = result.conf_int()
    fixed_names = list(result.fe_params.index)
    coefficients = []
    for term in fixed_names:
        coefficients.append(
            {
                "model": name,
                "model_status": status,
                "term": term,
                "coefficient": float(result.params[term]),
                "standard_error": float(result.bse[term]),
                "p_value": float(result.pvalues[term]),
                "ci95_low": float(confidence.loc[term, 0]),
                "ci95_high": float(confidence.loc[term, 1]),
                "n": len(frame),
                "case_count": frame[group_field].nunique(),
                "session_count": frame["session_id"].nunique(),
            }
        )
    fit = ModelFit(name, status, result, formula, " | ".join(messages))
    return fit, pd.DataFrame(coefficients)


def _session_level_frame(data: pd.DataFrame, response: str) -> pd.DataFrame:
    """Collapse repeated attempts to independent session-level observations."""
    categorical = [
        "run_id",
        "case_cluster_id",
        "case_id",
        "session_id",
        "kex_group",
        "pki_chain_id",
        "pki_kind",
        "root_sig_alg",
        "leaf_sig_alg",
    ]
    fields = [*categorical, response]
    frame = data[fields].dropna(subset=[response]).copy()
    frame = frame[frame[response] > 0]
    if frame.empty:
        return frame
    return (
        frame.groupby(categorical, observed=True, dropna=False)[response]
        .mean()
        .reset_index()
    )


def fit_factorial_model(
    data: pd.DataFrame,
    *,
    name: str,
    response: str,
) -> tuple[ModelFit, pd.DataFrame, pd.DataFrame]:
    """Fit a full KEM by PKI fixed-effects model on session means."""
    frame = _session_level_frame(data, response)
    if (
        len(frame) < 12
        or frame["kex_group"].nunique() < 2
        or frame["pki_chain_id"].nunique() < 2
    ):
        fit = ModelFit(name, "insufficient_data", None, "", "too few factor levels")
        return fit, pd.DataFrame(), pd.DataFrame()

    frame["log_response"] = np.log(frame[response])
    terms = ["C(kex_group) * C(pki_chain_id)"]
    if frame["run_id"].nunique() > 1:
        terms.append("C(run_id)")
    formula = "log_response ~ " + " + ".join(terms)
    try:
        result = smf.ols(formula, frame).fit()
        robust = result.get_robustcov_results(
            cov_type="cluster", groups=frame["case_cluster_id"]
        )
        anova = sm.stats.anova_lm(result, typ=2).reset_index(
            names="term"
        )
        anova = anova.rename(
            columns={"F": "f_statistic", "PR(>F)": "p_value"}
        )
    except Exception as exc:
        fit = ModelFit(name, "model_error", None, formula, str(exc))
        return fit, pd.DataFrame(), pd.DataFrame()

    residual_row = anova[anova["term"] == "Residual"]
    residual_ss = (
        float(residual_row["sum_sq"].iloc[0]) if not residual_row.empty else math.nan
    )
    total_ss = float(anova["sum_sq"].sum())
    anova["model"] = name
    anova["response"] = response
    anova["eta_squared"] = anova["sum_sq"] / total_ss
    anova["partial_eta_squared"] = anova["sum_sq"] / (
        anova["sum_sq"] + residual_ss
    )
    anova.loc[anova["term"] == "Residual", "partial_eta_squared"] = np.nan
    anova["n"] = len(frame)
    anova["case_count"] = frame["case_cluster_id"].nunique()
    anova["session_count"] = frame["session_id"].nunique()
    anova["status"] = "ok"
    anova["formula"] = formula

    names = result.model.exog_names
    confidence = np.asarray(robust.conf_int())
    coefficients = pd.DataFrame(
        {
            "model": name,
            "model_status": "ok",
            "response": response,
            "term": names,
            "coefficient": np.asarray(robust.params),
            "standard_error": np.asarray(robust.bse),
            "p_value": np.asarray(robust.pvalues),
            "ci95_low": confidence[:, 0],
            "ci95_high": confidence[:, 1],
            "n": len(frame),
            "case_count": frame["case_cluster_id"].nunique(),
            "session_count": frame["session_id"].nunique(),
            "formula": formula,
        }
    )
    fit = ModelFit(name, "ok", result, formula)
    return fit, anova, coefficients


def fit_factorial_mixed_model(
    data: pd.DataFrame,
    *,
    name: str,
    response: str,
) -> tuple[ModelFit, pd.DataFrame]:
    """Fit a compact factorial mixed model with a PKI-chain random intercept."""
    frame = _session_level_frame(data, response)
    if (
        len(frame) < 20
        or frame["kex_group"].nunique() < 2
        or frame["pki_chain_id"].nunique() < 2
    ):
        fit = ModelFit(name, "insufficient_data", None, "", "too few factor levels")
        return fit, pd.DataFrame()

    frame["log_response"] = np.log(frame[response])
    # Root and leaf algorithms are encoded by the chain random effect. Including
    # them again as fixed effects makes the design matrix rank deficient.
    terms = ["C(kex_group) * C(pki_kind)"]
    if frame["run_id"].nunique() > 1:
        terms.append("C(run_id)")
    formula = "log_response ~ " + " + ".join(terms)
    try:
        model = smf.mixedlm(
            formula,
            frame,
            groups=frame["pki_chain_id"],
            re_formula="1",
        )
    except Exception as exc:
        return ModelFit(name, "model_error", None, formula, str(exc)), pd.DataFrame()

    result = None
    messages: list[str] = []
    for method in ("lbfgs", "powell"):
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                candidate = model.fit(method=method, reml=False, maxiter=2000)
            messages.extend(str(item.message) for item in caught)
            result = candidate
            if bool(candidate.converged):
                break
        except Exception as exc:
            messages.append(f"{method}: {exc}")
    if result is None:
        fit = ModelFit(name, "model_error", None, formula, " | ".join(messages))
        return fit, pd.DataFrame()

    status = "ok" if bool(result.converged) else "not_converged"
    confidence = result.conf_int()
    rows = []
    for term in result.fe_params.index:
        rows.append(
            {
                "model": name,
                "model_status": status,
                "response": response,
                "term": term,
                "coefficient": float(result.params[term]),
                "standard_error": float(result.bse[term]),
                "p_value": float(result.pvalues[term]),
                "ci95_low": float(confidence.loc[term, 0]),
                "ci95_high": float(confidence.loc[term, 1]),
                "n": len(frame),
                "case_count": frame["case_cluster_id"].nunique(),
                "session_count": frame["session_id"].nunique(),
                "pki_chain_count": frame["pki_chain_id"].nunique(),
                "formula": formula,
            }
        )
    fit = ModelFit(name, status, result, formula, " | ".join(messages))
    return fit, pd.DataFrame(rows)


def pareto_ranks(values: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Return non-dominated rank and original dominated-by count."""
    values = np.asarray(values, dtype=float)
    ranks = np.zeros(len(values), dtype=int)
    dominated_by = np.zeros(len(values), dtype=int)
    for index, point in enumerate(values):
        dominates_point = np.all(values <= point, axis=1) & np.any(
            values < point, axis=1
        )
        dominated_by[index] = int(dominates_point.sum())

    remaining = np.ones(len(values), dtype=bool)
    rank = 1
    while remaining.any():
        indexes = np.flatnonzero(remaining)
        current = values[indexes]
        dominance = np.all(
            current[:, None, :] <= current[None, :, :], axis=2
        ) & np.any(current[:, None, :] < current[None, :, :], axis=2)
        front = indexes[dominance.sum(axis=0) == 0]
        if not len(front):
            ranks[indexes] = rank
            break
        ranks[front] = rank
        remaining[front] = False
        rank += 1
    return ranks, dominated_by


def pareto_frontier(data: pd.DataFrame, quality: pd.DataFrame) -> pd.DataFrame:
    """Build a multi-objective Pareto table for benchmark configurations."""
    aggregations = {
        "kex_group": "first",
        "pki_chain_id": "first",
        "pki_kind": "first",
        "root_sig_alg": "first",
        "leaf_sig_alg": "first",
        "raw_handshake_ms": "mean",
        "handshake_energy_uj": "mean",
        "client_heap_peak_bytes": "max",
        "server_chain_bytes": "mean",
        "session_id": "nunique",
    }
    cases = data.groupby("case_id", observed=True).agg(aggregations).reset_index()
    cases = cases.rename(
        columns={
            "raw_handshake_ms": "mean_raw_handshake_ms",
            "handshake_energy_uj": "mean_handshake_energy_uj",
            "client_heap_peak_bytes": "max_client_heap_peak_bytes",
            "server_chain_bytes": "mean_server_chain_bytes",
            "session_id": "session_count",
        }
    )

    if not quality.empty and "reason" in quality:
        status = quality[quality["reason"].astype(str).str.startswith("status_")]
        if not status.empty:
            status = (
                status.groupby(["case_id", "reason"], observed=True)["count"]
                .sum()
                .unstack(fill_value=0)
            )
            status["recorded_attempt_count"] = status.sum(axis=1)
            status["success_count"] = status.get("status_success", 0)
            status["failure_count"] = (
                status["recorded_attempt_count"] - status["success_count"]
            )
            status["failure_rate"] = status["failure_count"] / status[
                "recorded_attempt_count"
            ].replace(0, np.nan)
            cases = cases.merge(
                status[
                    [
                        "recorded_attempt_count",
                        "success_count",
                        "failure_count",
                        "failure_rate",
                    ]
                ],
                left_on="case_id",
                right_index=True,
                how="left",
            )
    for field, default in (
        ("recorded_attempt_count", len(data)),
        ("success_count", len(data)),
        ("failure_count", 0),
        ("failure_rate", 0.0),
    ):
        if field not in cases:
            cases[field] = default
        cases[field] = cases[field].fillna(default)

    objectives = [
        "mean_raw_handshake_ms",
        "mean_handshake_energy_uj",
        "max_client_heap_peak_bytes",
        "mean_server_chain_bytes",
        "failure_rate",
    ]
    cases["pareto_status"] = "complete"
    complete = cases[objectives].notna().all(axis=1)
    cases.loc[~complete, "pareto_status"] = "incomplete_objectives"
    cases["pareto_rank"] = np.nan
    cases["dominated_by_count"] = np.nan
    cases["distance_to_ideal"] = np.nan
    cases["pareto_optimal"] = False
    if complete.any():
        values = cases.loc[complete, objectives].to_numpy(dtype=float)
        ranks, dominated_by = pareto_ranks(values)
        minimum = values.min(axis=0)
        spread = values.max(axis=0) - minimum
        spread[spread == 0] = 1.0
        normalized = (values - minimum) / spread
        cases.loc[complete, "pareto_rank"] = ranks
        cases.loc[complete, "dominated_by_count"] = dominated_by
        cases.loc[complete, "distance_to_ideal"] = np.sqrt(
            np.square(normalized).sum(axis=1)
        )
        cases.loc[complete, "pareto_optimal"] = ranks == 1
    return cases.sort_values(
        ["pareto_rank", "distance_to_ideal", "case_id"], na_position="last"
    ).reset_index(drop=True)


def add_outlier_flags(data: pd.DataFrame) -> pd.DataFrame:
    output = data.copy()
    output["outlier_standardized_residual"] = False
    output["outlier_cooks_distance"] = False
    fields = (
        "handshake_energy_uj",
        "signature_time_ms",
        "kem_time_ms",
        "communication_overhead_ms",
        "l2cap_tx_bytes",
    )
    frame = output[list(fields)].dropna()
    if len(frame) <= len(fields) + 2:
        return output
    design = sm.add_constant(frame[list(fields[1:])], has_constant="add")
    ols = sm.OLS(np.log(frame["handshake_energy_uj"]), design).fit()
    influence = ols.get_influence()
    standardized = np.abs(influence.resid_studentized_internal)
    cooks = influence.cooks_distance[0]
    output.loc[frame.index, "outlier_standardized_residual"] = standardized > 3
    output.loc[frame.index, "outlier_cooks_distance"] = cooks > 4 / len(frame)
    return output


def confidence_half_width(values: Iterable[float]) -> float:
    clean = np.asarray([value for value in values if math.isfinite(value)])
    if len(clean) < 2:
        return math.nan
    critical = stats.t.ppf(0.975, len(clean) - 1)
    return float(critical * clean.std(ddof=1) / math.sqrt(len(clean)))


def nist_comparisons(data: pd.DataFrame) -> pd.DataFrame:
    rows: list[dict[str, object]] = []
    specs = (
        (
            "kem",
            "kex_nist_level",
            "kem_time_ms",
            "client_kem_energy_uj",
            "client_kem_edp_mj_s",
        ),
        (
            "signature",
            "sig_nist_level",
            "signature_time_ms",
            "client_signature_energy_uj",
            "client_signature_edp_mj_s",
        ),
    )
    for domain, level_field, *metrics in specs:
        for metric in metrics:
            subset = data[[level_field, metric]].dropna()
            coefficient, p_value, n, status = safe_correlation(
                subset[level_field], subset[metric], "spearman"
            )
            rows.append(
                {
                    "analysis": "ordinal_spearman",
                    "domain": domain,
                    "metric": metric,
                    "nist_level": "",
                    "n": n,
                    "mean": "",
                    "median": "",
                    "stddev": "",
                    "ci95_half_width": "",
                    "coefficient": coefficient,
                    "p_value": p_value,
                    "status": status,
                }
            )
            for level, values in subset.groupby(level_field)[metric]:
                clean = values.dropna().astype(float)
                rows.append(
                    {
                        "analysis": "descriptive",
                        "domain": domain,
                        "metric": metric,
                        "nist_level": int(level),
                        "n": len(clean),
                        "mean": clean.mean(),
                        "median": clean.median(),
                        "stddev": clean.std(ddof=1),
                        "ci95_half_width": confidence_half_width(clean),
                        "coefficient": "",
                        "p_value": "",
                        "status": "ok",
                    }
                )
            rows.extend(
                categorical_nist_model(
                    data,
                    domain=domain,
                    level_field=level_field,
                    metric=metric,
                )
            )
    result = pd.DataFrame(rows)
    result["p_value_adjusted_bh"] = np.nan
    indexes = result.index[pd.to_numeric(result["p_value"], errors="coerce").notna()]
    if len(indexes):
        adjusted = benjamini_hochberg(
            pd.to_numeric(result.loc[indexes, "p_value"])
        )
        result.loc[indexes, "p_value_adjusted_bh"] = adjusted
    return result


def benjamini_hochberg(values: Iterable[float]) -> np.ndarray:
    return np.asarray(
        multipletests(np.asarray(list(values), dtype=float), method="fdr_bh")[1]
    )


def categorical_nist_model(
    data: pd.DataFrame,
    *,
    domain: str,
    level_field: str,
    metric: str,
) -> list[dict[str, object]]:
    fields = [
        level_field,
        metric,
        "algorithm_category",
        "run_id",
        "case_id",
        "session_id",
    ]
    frame = data[fields].dropna().copy()
    if (
        len(frame) < 12
        or frame[level_field].nunique() < 2
        or frame["case_id"].nunique() < 2
    ):
        return [
            {
                "analysis": "categorical_mixed_model",
                "domain": domain,
                "metric": metric,
                "status": "insufficient_data",
            }
        ]
    frame["log_metric"] = np.log(frame[metric])
    terms = [f"C({level_field})", "C(algorithm_category)"]
    if frame["run_id"].nunique() > 1:
        terms.append("C(run_id)")
    formula = "log_metric ~ " + " + ".join(terms)
    try:
        model = smf.mixedlm(
            formula,
            frame,
            groups=frame["case_id"],
            re_formula="1",
            vc_formula={"session": "0 + C(session_id)"},
        )
        result = None
        for method in ("lbfgs", "powell"):
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    candidate = model.fit(
                        method=method, reml=False, maxiter=2000
                    )
                result = candidate
                if bool(candidate.converged):
                    break
            except Exception:
                continue
        if result is None:
            raise RuntimeError("all mixed-model optimizers failed")
    except Exception as exc:
        return [
            {
                "analysis": "categorical_mixed_model",
                "domain": domain,
                "metric": metric,
                "status": "model_error",
                "message": str(exc),
            }
        ]

    status = "ok" if bool(result.converged) else "not_converged"
    confidence = result.conf_int()
    output = []
    for term in result.fe_params.index:
        if not term.startswith(f"C({level_field})"):
            continue
        output.append(
            {
                "analysis": "categorical_mixed_model",
                "domain": domain,
                "metric": metric,
                "nist_level": term,
                "n": len(frame),
                "coefficient": float(result.params[term]),
                "standard_error": float(result.bse[term]),
                "p_value": float(result.pvalues[term]),
                "ci95_low": float(confidence.loc[term, 0]),
                "ci95_high": float(confidence.loc[term, 1]),
                "status": status,
                "formula": formula,
            }
        )
    return output or [
        {
            "analysis": "categorical_mixed_model",
            "domain": domain,
            "metric": metric,
            "status": "no_level_contrast",
            "formula": formula,
        }
    ]


def signature_size_analysis(
    data: pd.DataFrame,
    *,
    bootstrap_iterations: int,
    seed: int,
) -> pd.DataFrame:
    base = correlation_table(
        data,
        bootstrap_iterations=bootstrap_iterations,
        seed=seed + 2,
    )
    base = base[base["analysis"] == "signature_size_communication"].copy()
    predictors = (
        "sig_signature_bytes",
        "kex_public_key_bytes",
        "kex_ciphertext_bytes",
        "total_l2cap_bytes",
    )
    fit, coefficients = fit_mixed_model(
        data,
        name="signature_size_overhead_mixed",
        response="communication_overhead_ms",
        predictors=predictors,
    )
    base["model_status"] = ""
    if coefficients.empty:
        base.loc[len(base)] = {
            "analysis": "mixed_model",
            "status": fit.status,
            "model_status": fit.status,
        }
        return base
    coefficients = coefficients.rename(columns={"model": "analysis"})
    coefficients["status"] = fit.status
    return pd.concat([base, coefficients], ignore_index=True, sort=False)


def save_frame(frame: pd.DataFrame, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(path, index=False, quoting=csv.QUOTE_MINIMAL)


def plot_between_within_correlations(
    correlations: pd.DataFrame,
    output: Path,
) -> None:
    """Plot pooled, between-case, and within-case coefficients side by side."""
    figure, axes = plt.subplots(1, 2, figsize=(17, 7), sharey=True)
    level_order = ("pooled", "between_case", "within_case")
    colors = {
        "pooled": "#33658a",
        "between_case": "#f6ae2d",
        "within_case": "#2f855a",
    }
    analyses = list(dict.fromkeys(correlations["analysis"].astype(str)))
    positions = np.arange(len(analyses), dtype=float)
    offsets = np.linspace(-0.22, 0.22, len(level_order))
    for axis, method in zip(axes, ("pearson", "spearman"), strict=True):
        subset = correlations[correlations["method"] == method]
        for offset, level in zip(offsets, level_order, strict=True):
            rows = subset[subset["level"] == level].set_index("analysis")
            coefficients = np.asarray(
                [rows.at[name, "coefficient"] if name in rows.index else np.nan for name in analyses],
                dtype=float,
            )
            lows = np.asarray(
                [rows.at[name, "ci95_low"] if name in rows.index else np.nan for name in analyses],
                dtype=float,
            )
            highs = np.asarray(
                [rows.at[name, "ci95_high"] if name in rows.index else np.nan for name in analyses],
                dtype=float,
            )
            valid = np.isfinite(coefficients)
            axis.scatter(
                positions[valid] + offset,
                coefficients[valid],
                color=colors[level],
                label=level.replace("_", " "),
                zorder=3,
            )
            ci_valid = valid & np.isfinite(lows) & np.isfinite(highs)
            if ci_valid.any():
                axis.errorbar(
                    positions[ci_valid] + offset,
                    coefficients[ci_valid],
                    yerr=np.vstack(
                        [
                            coefficients[ci_valid] - lows[ci_valid],
                            highs[ci_valid] - coefficients[ci_valid],
                        ]
                    ),
                    fmt="none",
                    color=colors[level],
                    capsize=3,
                    linewidth=1,
                )
        axis.axhline(0, color="black", linewidth=1)
        axis.set_title(method.capitalize())
        axis.set_xticks(positions, [name.replace("_", " ") for name in analyses])
        axis.tick_params(axis="x", rotation=35)
        axis.set_ylim(-1.05, 1.05)
        axis.legend(frameon=False)
    axes[0].set_ylabel("Correlation coefficient (95% case-cluster bootstrap CI)")
    figure.tight_layout()
    figure.savefig(output)
    plt.close(figure)


def plot_factorial_effects(anova: pd.DataFrame, output: Path) -> None:
    """Compare KEM, PKI, and interaction effect sizes."""
    required = {"term", "partial_eta_squared", "response"}
    if required.issubset(anova.columns):
        subset = anova[
            (anova["term"] != "Residual")
            & pd.to_numeric(
                anova["partial_eta_squared"], errors="coerce"
            ).notna()
        ].copy()
    else:
        subset = pd.DataFrame()
    figure, axis = plt.subplots(figsize=(12, 6))
    if subset.empty:
        axis.text(0.5, 0.5, "Factorial model unavailable", ha="center", va="center")
        axis.axis("off")
    else:
        labels = {
            "C(kex_group)": "KEM",
            "C(pki_chain_id)": "PKI chain",
            "C(kex_group):C(pki_chain_id)": "KEM x PKI",
        }
        subset["factor"] = subset["term"].map(labels).fillna(subset["term"])
        subset["response_label"] = subset["response"].map(
            {
                "raw_handshake_ms": "Handshake time",
                "handshake_energy_uj": "Handshake energy",
            }
        ).fillna(subset["response"])
        sns.barplot(
            data=subset,
            x="factor",
            y="partial_eta_squared",
            hue="response_label",
            ax=axis,
            palette="colorblind",
        )
        axis.set_xlabel("")
        axis.set_ylabel("Partial eta squared")
        axis.legend(title="Response", frameon=False)
    figure.tight_layout()
    figure.savefig(output)
    plt.close(figure)


def plot_mechanistic_coefficients(
    coefficients: pd.DataFrame,
    output: Path,
) -> None:
    """Forest-plot standardized mechanistic effects for time and energy."""
    subset = coefficients[
        coefficients.get("term", pd.Series(dtype=str)).astype(str).str.startswith("z_")
    ].copy()
    models = list(dict.fromkeys(subset.get("model", pd.Series(dtype=str)).astype(str)))
    figure, axes = plt.subplots(
        max(1, len(models)), 1, figsize=(11, max(5, 4.5 * len(models))), squeeze=False
    )
    for axis, model_name in zip(axes.flat, models, strict=False):
        rows = subset[subset["model"] == model_name].sort_values("coefficient")
        positions = np.arange(len(rows))
        axis.errorbar(
            rows["coefficient"],
            positions,
            xerr=np.vstack(
                [
                    rows["coefficient"] - rows["ci95_low"],
                    rows["ci95_high"] - rows["coefficient"],
                ]
            ),
            fmt="o",
            capsize=4,
        )
        axis.axvline(0, color="black", linewidth=1)
        axis.set_yticks(positions, rows["term"].str.removeprefix("z_"))
        axis.set_title(model_name.replace("_", " "))
        axis.set_xlabel("Fully standardized coefficient (95% CI)")
    for axis in axes.flat[len(models):]:
        axis.axis("off")
    if not models:
        axes.flat[0].text(0.5, 0.5, "Mechanistic models unavailable", ha="center")
        axes.flat[0].axis("off")
    figure.tight_layout()
    figure.savefig(output)
    plt.close(figure)


def plot_pareto_frontier(frontier: pd.DataFrame, output: Path) -> None:
    """Highlight multi-objective Pareto cases in two interpretable projections."""
    complete = frontier[frontier["pareto_status"] == "complete"].copy()
    figure, axes = plt.subplots(1, 2, figsize=(16, 6))
    projections = (
        (
            "mean_raw_handshake_ms",
            "mean_handshake_energy_uj",
            "Mean handshake time (ms)",
            "Mean handshake energy (uJ)",
        ),
        (
            "mean_server_chain_bytes",
            "max_client_heap_peak_bytes",
            "Mean transmitted certificate chain (bytes)",
            "Maximum client heap peak (bytes)",
        ),
    )
    for axis, (x_name, y_name, x_label, y_label) in zip(
        axes, projections, strict=True
    ):
        if complete.empty:
            axis.text(0.5, 0.5, "Pareto objectives unavailable", ha="center")
            axis.axis("off")
            continue
        sns.scatterplot(
            data=complete,
            x=x_name,
            y=y_name,
            hue="pki_kind",
            style="pareto_optimal",
            size="failure_rate",
            sizes=(35, 160),
            alpha=0.72,
            ax=axis,
        )
        pareto = complete[complete["pareto_optimal"]]
        axis.scatter(
            pareto[x_name],
            pareto[y_name],
            facecolors="none",
            edgecolors="black",
            linewidths=1.4,
            s=190,
            label="Pareto front",
        )
        axis.set_xlabel(x_label)
        axis.set_ylabel(y_label)
        axis.legend(frameon=False, fontsize=8)
    figure.tight_layout()
    figure.savefig(output)
    plt.close(figure)


def plot_correlations(
    data: pd.DataFrame,
    output: Path,
) -> None:
    figure, axes = plt.subplots(2, 3, figsize=(18, 10))
    for axis, (_, x_name, y_name) in zip(
        axes.flat, CORRELATION_SPECS, strict=False
    ):
        subset = data[[x_name, y_name, "algorithm_category"]].dropna()
        sns.scatterplot(
            data=subset,
            x=x_name,
            y=y_name,
            hue="algorithm_category",
            ax=axis,
            alpha=0.75,
        )
        if len(subset) >= 3 and subset[x_name].nunique() > 1:
            sns.regplot(
                data=subset,
                x=x_name,
                y=y_name,
                scatter=False,
                color="black",
                ax=axis,
            )
        axis.set_title(f"{x_name} vs {y_name}")
    axes.flat[-1].axis("off")
    figure.tight_layout()
    figure.savefig(output)
    plt.close(figure)


def plot_partial_residuals(
    residuals: dict[str, tuple[pd.Series, pd.Series]],
    output: Path,
) -> None:
    columns = 2
    rows = max(1, math.ceil(len(residuals) / columns))
    figure, axes = plt.subplots(
        rows, columns, figsize=(13, 5 * rows), squeeze=False
    )
    for axis, (name, values) in zip(axes.flat, residuals.items(), strict=False):
        frame = pd.DataFrame({"x_residual": values[0], "y_residual": values[1]})
        sns.regplot(
            data=frame,
            x="x_residual",
            y="y_residual",
            ax=axis,
        )
        axis.set_title(name.replace("_", " "))
    for axis in axes.flat[len(residuals):]:
        axis.axis("off")
    figure.tight_layout()
    figure.savefig(output)
    plt.close(figure)


def plot_standardized_coefficients(
    coefficients: pd.DataFrame,
    output: Path,
) -> None:
    subset = coefficients[
        coefficients["term"].astype(str).str.startswith("z_")
    ].copy()
    figure, axis = plt.subplots(figsize=(10, 5))
    if subset.empty:
        axis.text(0.5, 0.5, "Mixed model unavailable", ha="center", va="center")
        axis.axis("off")
    else:
        subset = subset.sort_values("coefficient")
        positions = np.arange(len(subset))
        lower = subset["coefficient"] - subset["ci95_low"]
        upper = subset["ci95_high"] - subset["coefficient"]
        axis.errorbar(
            subset["coefficient"],
            positions,
            xerr=np.vstack([lower, upper]),
            fmt="o",
            capsize=4,
        )
        axis.axvline(0, color="black", linewidth=1)
        axis.set_yticks(positions, subset["term"].str.removeprefix("z_"))
        axis.set_xlabel("Fully standardized coefficient (95% CI)")
    figure.tight_layout()
    figure.savefig(output)
    plt.close(figure)


def plot_nist(data: pd.DataFrame, output: Path) -> None:
    figure, axes = plt.subplots(2, 3, figsize=(17, 10))
    specs = (
        ("kex_nist_level", "kem_time_ms"),
        ("kex_nist_level", "client_kem_energy_uj"),
        ("kex_nist_level", "client_kem_edp_mj_s"),
        ("sig_nist_level", "signature_time_ms"),
        ("sig_nist_level", "client_signature_energy_uj"),
        ("sig_nist_level", "client_signature_edp_mj_s"),
    )
    for axis, (level, metric) in zip(axes.flat, specs, strict=True):
        subset = data[[level, metric]].dropna()
        sns.boxplot(data=subset, x=level, y=metric, ax=axis, color="#4c956c")
        sns.stripplot(
            data=subset,
            x=level,
            y=metric,
            ax=axis,
            color="black",
            alpha=0.35,
            size=3,
        )
    figure.tight_layout()
    figure.savefig(output)
    plt.close(figure)


def plot_signature_size(data: pd.DataFrame, output: Path) -> None:
    figure, axis = plt.subplots(figsize=(10, 6))
    subset = data[
        ["sig_signature_bytes", "communication_overhead_ms", "algorithm_category"]
    ].dropna()
    sns.scatterplot(
        data=subset,
        x="sig_signature_bytes",
        y="communication_overhead_ms",
        hue="algorithm_category",
        ax=axis,
    )
    if len(subset) >= 3 and subset["sig_signature_bytes"].nunique() > 1:
        sns.regplot(
            data=subset,
            x="sig_signature_bytes",
            y="communication_overhead_ms",
            scatter=False,
            color="black",
            ax=axis,
        )
    figure.tight_layout()
    figure.savefig(output)
    plt.close(figure)


def plot_power_edp(data: pd.DataFrame, output: Path) -> None:
    fields = (
        ("handshake_power_mw", "Handshake mean power (mW)"),
        ("handshake_edp_mj_s", "Handshake EDP (mJ s)"),
    )
    figure, axes = plt.subplots(1, 2, figsize=(13, 5))
    for axis, (metric, label) in zip(axes, fields, strict=True):
        sns.boxplot(
            data=data,
            x="algorithm_category",
            y=metric,
            ax=axis,
            color="#f4a261",
        )
        sns.stripplot(
            data=data,
            x="algorithm_category",
            y=metric,
            ax=axis,
            color="black",
            alpha=0.4,
            size=3,
        )
        axis.set_ylabel(label)
    figure.tight_layout()
    figure.savefig(output)
    plt.close(figure)


def plot_model_diagnostics(fit: ModelFit, output: Path) -> None:
    figure, axes = plt.subplots(1, 2, figsize=(12, 5))
    if fit.result is None:
        for axis in axes:
            axis.text(0.5, 0.5, f"Model unavailable: {fit.status}", ha="center")
            axis.axis("off")
    else:
        fitted = np.asarray(fit.result.fittedvalues)
        residuals = np.asarray(fit.result.resid)
        axes[0].scatter(fitted, residuals, alpha=0.7)
        axes[0].axhline(0, color="black", linewidth=1)
        axes[0].set_xlabel("Fitted values")
        axes[0].set_ylabel("Residuals")
        sm.qqplot(residuals, line="45", ax=axes[1])
    figure.tight_layout()
    figure.savefig(output)
    plt.close(figure)


def write_diagnostics(
    path: Path,
    fits: Sequence[ModelFit],
    data: pd.DataFrame,
) -> None:
    predictors = data[
        [
            "signature_time_ms",
            "kem_time_ms",
            "communication_overhead_ms",
            "l2cap_tx_bytes",
        ]
    ].dropna()
    lines = [
        f"accepted_rows={len(data)}",
        f"cases={data['case_id'].nunique()}",
        f"sessions={data['session_id'].nunique()}",
        (
            "handshake_power_relative_error_mean="
            f"{data['handshake_power_relative_error'].mean():.6f}"
        ),
        (
            "handshake_power_relative_error_max="
            f"{data['handshake_power_relative_error'].max():.6f}"
        ),
        "",
        "predictor_correlations:",
        predictors.corr().to_string(),
        "",
    ]
    if len(predictors) > 5:
        design = sm.add_constant(predictors, has_constant="add")
        for column in predictors:
            others = [item for item in design.columns if item not in {column}]
            r_squared = sm.OLS(design[column], design[others]).fit().rsquared
            vif = math.inf if r_squared >= 1 else 1 / (1 - r_squared)
            lines.append(f"VIF {column}={vif:.6f}")
    for fit in fits:
        lines.extend(
            [
                "",
                f"model={fit.name}",
                f"status={fit.status}",
                f"formula={fit.formula}",
                f"message={fit.message}",
                str(fit.result.summary()) if fit.result is not None else "",
            ]
        )
    path.write_text("\n".join(lines) + "\n")


def default_output_directory(run_dirs: Sequence[Path]) -> Path:
    if len(run_dirs) == 1:
        identity = run_dirs[0].name
    else:
        identity = f"{run_dirs[0].name}__{run_dirs[-1].name}__n{len(run_dirs)}"
    return PROJECT_ROOT / "graphic" / "out" / "statistics" / identity


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    run_dirs = [resolve_run_dir(value) for value in args.run_dirs]
    out_dir = (args.out_dir or default_output_directory(run_dirs)).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    extension = "png" if args.generate_png else "pdf"
    sns.set_theme(style="whitegrid")

    data, quality = load_attempt_data(
        run_dirs,
        include_reconnects=args.include_reconnects,
    )
    if data.empty:
        save_frame(quality, out_dir / "data_quality.csv")
        raise SystemExit("No valid powered benchmark attempts were found")

    data = add_outlier_flags(data)
    correlations = correlation_table(
        data,
        bootstrap_iterations=args.bootstrap_iterations,
        seed=args.seed,
    )
    between_within = between_within_correlation_table(
        data,
        bootstrap_iterations=args.bootstrap_iterations,
        seed=args.seed,
    )
    partial, partial_residuals = partial_correlation_table(
        data,
        bootstrap_iterations=args.bootstrap_iterations,
        seed=args.seed,
    )

    data["log_handshake_energy_uj"] = np.log(data["handshake_energy_uj"])
    data["log_raw_handshake_ms"] = np.log(data["raw_handshake_ms"])
    predictors = (
        "signature_time_ms",
        "kem_time_ms",
        "communication_overhead_ms",
        "l2cap_tx_bytes",
    )
    primary_fit, primary_coefficients = fit_mixed_model(
        data,
        name="handshake_energy",
        response="log_handshake_energy_uj",
        predictors=predictors,
    )
    standardized_fit, standardized_coefficients = fit_mixed_model(
        data,
        name="handshake_energy_standardized",
        response="log_handshake_energy_uj",
        predictors=predictors,
        standardized=True,
    )
    time_fit, time_coefficients = fit_mixed_model(
        data,
        name="handshake_time_mechanistic",
        response="log_raw_handshake_ms",
        predictors=predictors,
    )
    time_standardized_fit, time_standardized_coefficients = fit_mixed_model(
        data,
        name="handshake_time_mechanistic_standardized",
        response="log_raw_handshake_ms",
        predictors=predictors,
        standardized=True,
    )
    mechanistic_coefficients = pd.concat(
        [
            primary_coefficients,
            standardized_coefficients,
            time_coefficients,
            time_standardized_coefficients,
        ],
        ignore_index=True,
        sort=False,
    )

    factorial_fits: list[ModelFit] = []
    factorial_anova_parts: list[pd.DataFrame] = []
    factorial_coefficient_parts: list[pd.DataFrame] = []
    factorial_mixed_fits: list[ModelFit] = []
    factorial_mixed_parts: list[pd.DataFrame] = []
    for response, label in (
        ("raw_handshake_ms", "handshake_time"),
        ("handshake_energy_uj", "handshake_energy"),
    ):
        factorial_fit, anova, coefficients = fit_factorial_model(
            data,
            name=f"{label}_kem_x_pki",
            response=response,
        )
        factorial_fits.append(factorial_fit)
        factorial_anova_parts.append(anova)
        factorial_coefficient_parts.append(coefficients)
        mixed_fit, mixed_coefficients = fit_factorial_mixed_model(
            data,
            name=f"{label}_factorial_mixed",
            response=response,
        )
        factorial_mixed_fits.append(mixed_fit)
        factorial_mixed_parts.append(mixed_coefficients)
    factorial_anova = pd.concat(
        factorial_anova_parts, ignore_index=True, sort=False
    )
    factorial_coefficients = pd.concat(
        factorial_coefficient_parts, ignore_index=True, sort=False
    )
    factorial_mixed_coefficients = pd.concat(
        factorial_mixed_parts, ignore_index=True, sort=False
    )
    pareto = pareto_frontier(data, quality)
    nist = nist_comparisons(data)
    signature_size = signature_size_analysis(
        data,
        bootstrap_iterations=args.bootstrap_iterations,
        seed=args.seed,
    )

    save_frame(data, out_dir / "analysis_dataset.csv")
    save_frame(quality, out_dir / "data_quality.csv")
    save_frame(correlations, out_dir / "correlations.csv")
    save_frame(
        between_within,
        out_dir / "between_within_correlations.csv",
    )
    save_frame(partial, out_dir / "partial_correlations.csv")
    save_frame(primary_coefficients, out_dir / "mixed_model_coefficients.csv")
    save_frame(
        standardized_coefficients,
        out_dir / "standardized_coefficients.csv",
    )
    save_frame(
        mechanistic_coefficients,
        out_dir / "mechanistic_mixed_model_coefficients.csv",
    )
    save_frame(factorial_anova, out_dir / "factorial_anova.csv")
    save_frame(
        factorial_coefficients,
        out_dir / "factorial_model_coefficients.csv",
    )
    save_frame(
        factorial_mixed_coefficients,
        out_dir / "factorial_mixed_model_coefficients.csv",
    )
    save_frame(pareto, out_dir / "pareto_frontier.csv")
    save_frame(nist, out_dir / "nist_comparisons.csv")
    save_frame(signature_size, out_dir / "signature_size_overhead.csv")

    manifest = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "run_dirs": [str(path) for path in run_dirs],
        "seed": args.seed,
        "bootstrap_iterations": args.bootstrap_iterations,
        "include_reconnects": args.include_reconnects,
        "accepted_attempts": len(data),
        "case_count": int(data["case_id"].nunique()),
        "session_count": int(data["session_id"].nunique()),
        "primary_model_status": primary_fit.status,
        "standardized_model_status": standardized_fit.status,
        "mechanistic_time_model_status": time_fit.status,
        "mechanistic_time_standardized_model_status": time_standardized_fit.status,
        "factorial_model_statuses": {
            fit.name: fit.status for fit in factorial_fits
        },
        "factorial_mixed_model_statuses": {
            fit.name: fit.status for fit in factorial_mixed_fits
        },
        "pareto_front_count": int(pareto["pareto_optimal"].sum()),
    }
    (out_dir / "analysis_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n"
    )
    write_diagnostics(
        out_dir / "model_diagnostics.txt",
        (
            primary_fit,
            standardized_fit,
            time_fit,
            time_standardized_fit,
            *factorial_fits,
            *factorial_mixed_fits,
        ),
        data,
    )

    plot_correlations(data, out_dir / f"time_energy_correlations.{extension}")
    plot_between_within_correlations(
        between_within,
        out_dir / f"between_within_correlations.{extension}",
    )
    plot_partial_residuals(
        partial_residuals,
        out_dir / f"partial_correlation_residuals.{extension}",
    )
    plot_standardized_coefficients(
        standardized_coefficients,
        out_dir / f"standardized_coefficients.{extension}",
    )
    plot_mechanistic_coefficients(
        pd.concat(
            [standardized_coefficients, time_standardized_coefficients],
            ignore_index=True,
            sort=False,
        ),
        out_dir / f"mechanistic_standardized_coefficients.{extension}",
    )
    plot_factorial_effects(
        factorial_anova,
        out_dir / f"factorial_effect_sizes.{extension}",
    )
    plot_pareto_frontier(
        pareto,
        out_dir / f"pareto_frontier.{extension}",
    )
    plot_nist(data, out_dir / f"nist_time_energy.{extension}")
    plot_signature_size(
        data,
        out_dir / f"signature_size_overhead.{extension}",
    )
    plot_power_edp(data, out_dir / f"power_and_edp.{extension}")
    plot_model_diagnostics(
        primary_fit,
        out_dir / f"mixed_model_diagnostics.{extension}",
    )

    print(f"attempts={len(data)}")
    print(f"cases={data['case_id'].nunique()}")
    print(f"sessions={data['session_id'].nunique()}")
    print(f"primary_model_status={primary_fit.status}")
    print(f"standardized_model_status={standardized_fit.status}")
    print(f"mechanistic_time_model_status={time_fit.status}")
    print(
        "factorial_model_statuses="
        + ",".join(f"{fit.name}:{fit.status}" for fit in factorial_fits)
    )
    print(
        "factorial_mixed_model_statuses="
        + ",".join(f"{fit.name}:{fit.status}" for fit in factorial_mixed_fits)
    )
    print(f"pareto_front_count={int(pareto['pareto_optimal'].sum())}")
    print(f"output={out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
