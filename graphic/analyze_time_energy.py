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
    session_text = data["session"].fillna(-1).astype(int).astype(str)
    data["session_id"] = (
        data["run_id"].astype(str)
        + "::"
        + data["case_id"].astype(str)
        + "::"
        + session_text
    )
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
) -> tuple[float, float, int]:
    if iterations == 0 or frame.empty:
        return math.nan, math.nan, 0
    clusters = frame["session_id"].dropna().unique()
    if len(clusters) < 2:
        return math.nan, math.nan, 0
    grouped = {cluster: frame[frame["session_id"] == cluster] for cluster in clusters}
    values: list[float] = []
    for _ in range(iterations):
        selected = rng.choice(clusters, size=len(clusters), replace=True)
        sample = pd.concat(
            [grouped[cluster] for cluster in selected],
            ignore_index=True,
        )
        value = statistic(sample)
        if math.isfinite(value):
            values.append(value)
    if len(values) < max(20, iterations // 10):
        return math.nan, math.nan, len(values)
    low, high = np.percentile(values, [2.5, 97.5])
    return float(low), float(high), len(values)


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

            def calculate(sample: pd.DataFrame) -> float:
                return safe_correlation(
                    sample[x_name], sample[y_name], method
                )[0]

            ci_low, ci_high, valid = cluster_bootstrap_ci(
                subset,
                calculate,
                iterations=bootstrap_iterations,
                rng=rng,
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
) -> tuple[float, float, int, str]:
    fields = [x_name, y_name, *controls, "run_id"]
    subset = frame[fields].dropna().copy()
    if len(subset) <= len(controls) + 2:
        return math.nan, math.nan, len(subset), "insufficient_data"
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
    controls = ("kem_time_ms", "communication_overhead_ms")
    specs = (
        ("signature_total_energy", "handshake_energy_uj"),
        ("signature_window_energy", "client_signature_energy_uj"),
    )
    rows: list[dict[str, object]] = []
    residuals: dict[str, tuple[pd.Series, pd.Series]] = {}
    rng = np.random.default_rng(seed + 1)
    for name, y_name in specs:
        fields = [
            "signature_time_ms",
            y_name,
            *controls,
            "run_id",
            "session_id",
        ]
        subset = data[fields].dropna().copy()
        coefficient, p_value, n, status = partial_coefficient(
            subset, "signature_time_ms", y_name, controls
        )

        def calculate(sample: pd.DataFrame) -> float:
            return partial_coefficient(
                sample, "signature_time_ms", y_name, controls
            )[0]

        ci_low, ci_high, valid = cluster_bootstrap_ci(
            subset,
            calculate,
            iterations=bootstrap_iterations,
            rng=rng,
        )
        if status == "ok":
            residuals[name] = (
                residualize(subset, "signature_time_ms", controls),
                residualize(subset, y_name, controls),
            )
        rows.append(
            {
                "analysis": name,
                "x": "signature_time_ms",
                "y": y_name,
                "controls": ";".join(controls),
                "n": n,
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
    fields = [
        response,
        *predictors,
        "run_id",
        "case_id",
        "session_id",
    ]
    frame = data[fields].dropna().copy()
    if len(frame) < max(12, len(predictors) + 6):
        fit = ModelFit(name, "insufficient_data", None, "", "too few rows")
        return fit, pd.DataFrame()
    if frame["case_id"].nunique() < 2 or frame["session_id"].nunique() < 2:
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
            groups=frame["case_id"],
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
                "case_count": frame["case_id"].nunique(),
                "session_count": frame["session_id"].nunique(),
            }
        )
    fit = ModelFit(name, status, result, formula, " | ".join(messages))
    return fit, pd.DataFrame(coefficients)


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
    figure, axes = plt.subplots(1, 2, figsize=(13, 5))
    for axis, (name, values) in zip(axes, residuals.items(), strict=False):
        frame = pd.DataFrame({"signature_residual": values[0], "energy_residual": values[1]})
        sns.regplot(
            data=frame,
            x="signature_residual",
            y="energy_residual",
            ax=axis,
        )
        axis.set_title(name.replace("_", " "))
    for axis in axes[len(residuals):]:
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
    partial, partial_residuals = partial_correlation_table(
        data,
        bootstrap_iterations=args.bootstrap_iterations,
        seed=args.seed,
    )

    data["log_handshake_energy_uj"] = np.log(data["handshake_energy_uj"])
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
    nist = nist_comparisons(data)
    signature_size = signature_size_analysis(
        data,
        bootstrap_iterations=args.bootstrap_iterations,
        seed=args.seed,
    )

    save_frame(data, out_dir / "analysis_dataset.csv")
    save_frame(quality, out_dir / "data_quality.csv")
    save_frame(correlations, out_dir / "correlations.csv")
    save_frame(partial, out_dir / "partial_correlations.csv")
    save_frame(primary_coefficients, out_dir / "mixed_model_coefficients.csv")
    save_frame(
        standardized_coefficients,
        out_dir / "standardized_coefficients.csv",
    )
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
    }
    (out_dir / "analysis_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n"
    )
    write_diagnostics(
        out_dir / "model_diagnostics.txt",
        (primary_fit, standardized_fit),
        data,
    )

    plot_correlations(data, out_dir / f"time_energy_correlations.{extension}")
    plot_partial_residuals(
        partial_residuals,
        out_dir / f"partial_correlation_residuals.{extension}",
    )
    plot_standardized_coefficients(
        standardized_coefficients,
        out_dir / f"standardized_coefficients.{extension}",
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
    print(f"output={out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
