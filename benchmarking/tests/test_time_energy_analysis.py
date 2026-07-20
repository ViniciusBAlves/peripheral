from __future__ import annotations

import math
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np
import pandas as pd


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "graphic"))

from analyze_time_energy import (
    add_power_and_edp_metrics,
    benjamini_hochberg,
    categorical_nist_model,
    cluster_bootstrap_ci,
    fit_mixed_model,
    load_attempt_data,
    partial_coefficient,
    safe_correlation,
)


class TimeEnergyAnalysisTests(unittest.TestCase):
    def test_loads_attempts_and_builds_unique_session_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            run = Path(tmpdir) / "run_a"
            for sequence, case_id in enumerate(("case_a", "case_b"), start=1):
                directory = run / "cases" / f"{sequence:03d}_{case_id}"
                directory.mkdir(parents=True)
                (directory / "attempts.csv").write_text(
                    "session,status,warmup,reconnect_count,power_status,"
                    "raw_handshake_ms,handshake_duration_ms,"
                    "handshake_energy_uj,kem_client_total_ms,"
                    "client_signature_total_ms,l2cap_tx_bytes,l2cap_rx_bytes,"
                    "power_profiler_vdd_mv\n"
                    "1,success,0,0,success,10,10,20,2,3,100,200,3000\n"
                )

            data, quality = load_attempt_data(
                [run], include_reconnects=False
            )

        self.assertEqual(len(data), 2)
        self.assertEqual(data["session_id"].nunique(), 2)
        self.assertEqual(set(data["case_id"]), {"case_a", "case_b"})
        total = quality[
            (quality["reason"] == "accepted_attempts")
            & (quality["case_id"] == "ALL")
        ]
        self.assertEqual(int(total["count"].iloc[0]), 2)

    def test_power_and_edp_units(self) -> None:
        frame = pd.DataFrame(
            {
                "power_profiler_vdd_mv": [3000.0],
                "raw_handshake_ms": [2000.0],
                "kem_time_ms": [500.0],
                "signature_time_ms": [250.0],
                "end_to_end_ms": [3000.0],
                "handshake_duration_ms": [2000.0],
                "handshake_energy_uj": [6000.0],
                "handshake_avg_current_ua": [1000.0],
                "client_kem_duration_ms": [500.0],
                "client_kem_energy_uj": [1500.0],
                "client_kem_avg_current_ua": [1000.0],
                "client_signature_duration_ms": [250.0],
                "client_signature_energy_uj": [750.0],
                "client_signature_avg_current_ua": [1000.0],
                "total_execution_duration_ms": [3000.0],
                "total_execution_energy_uj": [9000.0],
                "total_execution_avg_current_ua": [1000.0],
            }
        )
        add_power_and_edp_metrics(frame)
        self.assertAlmostEqual(frame.loc[0, "handshake_power_mw"], 3.0)
        self.assertAlmostEqual(frame.loc[0, "handshake_current_power_mw"], 3.0)
        self.assertAlmostEqual(frame.loc[0, "handshake_edp_mj_s"], 12.0)

    def test_partial_correlation_removes_controlled_confounder(self) -> None:
        rng = np.random.default_rng(17)
        control = rng.normal(size=400)
        x = 3 * control + rng.normal(scale=0.2, size=400)
        y = -2 * control + rng.normal(scale=0.2, size=400)
        frame = pd.DataFrame(
            {
                "x": x,
                "y": y,
                "control": control,
                "run_id": "run",
            }
        )
        raw = safe_correlation(frame["x"], frame["y"], "pearson")[0]
        partial = partial_coefficient(
            frame, "x", "y", ("control",)
        )[0]
        self.assertLess(raw, -0.9)
        self.assertLess(abs(partial), 0.15)

    def test_cluster_bootstrap_recovers_positive_correlation(self) -> None:
        frame = pd.DataFrame(
            {
                "session_id": np.repeat([f"s{i}" for i in range(8)], 5),
                "x": np.arange(40, dtype=float),
            }
        )
        frame["y"] = 2 * frame["x"] + 1
        low, high, valid = cluster_bootstrap_ci(
            frame,
            lambda sample: safe_correlation(
                sample["x"], sample["y"], "pearson"
            )[0],
            iterations=100,
            rng=np.random.default_rng(123),
        )
        self.assertGreater(valid, 90)
        self.assertAlmostEqual(low, 1.0)
        self.assertAlmostEqual(high, 1.0)

    def test_mixed_model_recovers_positive_standardized_effects(self) -> None:
        rng = np.random.default_rng(23)
        rows = []
        for case_index in range(8):
            case_effect = rng.normal(scale=0.08)
            for session in range(3):
                for attempt in range(4):
                    kem = rng.normal(100 + case_index * 4, 6)
                    signature = rng.normal(60 + case_index * 2, 5)
                    communication = rng.normal(400, 20)
                    tx_bytes = rng.normal(3000, 100)
                    response = (
                        0.008 * signature
                        + 0.004 * kem
                        + 0.0002 * communication
                        + 0.00001 * tx_bytes
                        + case_effect
                        + rng.normal(scale=0.03)
                    )
                    rows.append(
                        {
                            "log_energy": response,
                            "signature": signature,
                            "kem": kem,
                            "communication": communication,
                            "tx_bytes": tx_bytes,
                            "run_id": "run",
                            "case_id": f"case_{case_index}",
                            "session_id": f"case_{case_index}::{session}",
                        }
                    )
        frame = pd.DataFrame(rows)
        fit, coefficients = fit_mixed_model(
            frame,
            name="synthetic",
            response="log_energy",
            predictors=("signature", "kem", "communication", "tx_bytes"),
            standardized=True,
        )
        self.assertIn(fit.status, {"ok", "not_converged"})
        effects = coefficients.set_index("term")["coefficient"]
        self.assertGreater(effects["z_signature"], 0)
        self.assertGreater(effects["z_kem"], 0)

    def test_constant_correlation_is_reported(self) -> None:
        coefficient, _, n, status = safe_correlation(
            pd.Series([1.0, 1.0, 1.0]),
            pd.Series([1.0, 2.0, 3.0]),
            "pearson",
        )
        self.assertTrue(math.isnan(coefficient))
        self.assertEqual(n, 3)
        self.assertEqual(status, "constant_variable")

    def test_nist_model_reports_insufficient_levels(self) -> None:
        frame = pd.DataFrame(
            {
                "kex_nist_level": [1] * 12,
                "kem_time_ms": np.arange(1, 13, dtype=float),
                "algorithm_category": ["classic_only"] * 12,
                "run_id": ["run"] * 12,
                "case_id": np.repeat(["a", "b"], 6),
                "session_id": [f"s{i}" for i in range(12)],
            }
        )
        result = categorical_nist_model(
            frame,
            domain="kem",
            level_field="kex_nist_level",
            metric="kem_time_ms",
        )
        self.assertEqual(result[0]["status"], "insufficient_data")

    def test_benjamini_hochberg_adjustment_is_monotonic(self) -> None:
        adjusted = benjamini_hochberg([0.001, 0.01, 0.04])
        self.assertTrue(np.all(np.diff(adjusted) >= 0))


if __name__ == "__main__":
    unittest.main()
