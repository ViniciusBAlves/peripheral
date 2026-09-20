from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarklib.algorithms import SIGNATURES_BY_NAME
from run_certificate_benchmarks import (
    MAX_ALGORITHM_TIMEOUT_SEC,
    certificate_timeout,
    on_device_attempt_row,
    summarize,
)


class CertificateBenchmarkTests(unittest.TestCase):
    def test_timeout_is_capped_at_fifteen_minutes(self) -> None:
        self.assertEqual(
            certificate_timeout("RSA-PSS-15360", 20000),
            MAX_ALGORITHM_TIMEOUT_SEC,
        )
        self.assertEqual(certificate_timeout("ECDSA-P-256", 30), 30)

    def test_device_signature_sizes_match_shared_metadata(self) -> None:
        signature = SIGNATURES_BY_NAME["ML-DSA-44"]
        row = on_device_attempt_row(
            1,
            {"case_id": "certgen__ml_dsa_44"},
            signature,
            {
                "status": "success",
                "sig_public_key_bytes": "1312",
                "sig_private_key_bytes": "2560",
                "sig_signature_bytes": "2420",
            },
        )
        self.assertEqual(row["status"], "success")

        mismatched = on_device_attempt_row(
            1,
            {"case_id": "certgen__ml_dsa_44"},
            signature,
            {
                "status": "success",
                "sig_public_key_bytes": "1",
                "sig_private_key_bytes": "2",
                "sig_signature_bytes": "3",
            },
        )
        self.assertEqual(mismatched["status"], "fail")
        self.assertEqual(mismatched["error_code"], "metadata_mismatch")

    def test_signing_summary_reports_distribution(self) -> None:
        rows = [
            {
                "component": "on_device_certificate",
                "owner": "client",
                "cert_sig_alg": "ML-DSA-44",
                "sig_family": "pqc",
                "sig_nist_level": 2,
                "builder": "wolfssl-nrf5340",
                "generation_scope": "keypair_self_signed_x509_sign_and_verify",
                "status": "success",
                "certificate_sign_ms": value,
            }
            for value in ("100", "200", "300")
        ]
        result = summarize(rows)[0]
        self.assertEqual(result["median_certificate_sign_ms"], "200.000")
        self.assertEqual(result["p95_certificate_sign_ms"], "290.000")
        self.assertEqual(result["stddev_certificate_sign_ms"], "100.000")

    def test_timeout_preserves_progress_diagnostics(self) -> None:
        signature = SIGNATURES_BY_NAME["SLH-DSA-SHAKE-256s"]
        row = on_device_attempt_row(
            1,
            {"case_id": "certgen__slh_dsa_shake_256s"},
            signature,
            {
                "status": "timeout",
                "stage": "certificate_sign",
                "error": "timeout",
                "elapsed_us": "900000000",
                "stage_elapsed_us": "899000000",
                "certificate_total_us": "900000000",
                "client_cpu_cycles": "1000",
                "client_active_cycles": "1200",
                "client_idle_cycles": "300",
                "client_total_cycles": "1500",
                "client_cycle_hz": "128000000",
                "dwt_cycle_counter_supported": "1",
                "dwt_event_counters_supported": "1",
                "dwt_cyccnt": "123456",
                "dwt_cpicnt": "17",
                "dwt_exccnt": "3",
                "dwt_sleepcnt": "5",
                "dwt_lsucnt": "19",
                "dwt_foldcnt": "7",
                "dwt_cycle_counter_width_bits": "32",
                "dwt_event_counter_width_bits": "8",
                "dwt_counts_are_modulo": "1",
                "client_heap_peak_bytes": "8192",
                "client_stack_used_bytes": "4096",
                "_progress_reports": "180",
            },
        )
        self.assertEqual(row["status"], "timeout")
        self.assertEqual(row["client_cpu_cycles"], "1000")
        self.assertEqual(row["client_cpu_active_percent"], "80.000")
        self.assertEqual(row["client_cpu_idle_percent"], "20.000")
        self.assertEqual(row["dwt_cyccnt"], "123456")
        self.assertEqual(row["dwt_lsucnt"], "19")
        self.assertEqual(row["dwt_counts_are_modulo"], "1")
        self.assertEqual(row["timeout_elapsed_ms"], "900000.000")
        self.assertEqual(row["timeout_stage_elapsed_ms"], "899000.000")
        self.assertEqual(row["progress_reports"], "180")
        summary = summarize([row])[0]
        self.assertEqual(summary["status"], "timeout")
        self.assertEqual(summary["timeout_count"], 1)
        self.assertEqual(summary["last_timeout_stage"], "certificate_sign")
        self.assertEqual(summary["max_observed_dwt_cyccnt"], "123456")
        self.assertEqual(summary["max_observed_dwt_lsucnt"], "19")


if __name__ == "__main__":
    unittest.main()
