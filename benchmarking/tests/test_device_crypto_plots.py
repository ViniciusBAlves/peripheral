from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "graphic"))

from plot_device_crypto_benchmarks import (
    aggregate_certificate_rows,
    aggregate_kem_rows,
    detect_benchmark_type,
    write_latex_table,
)


class DeviceCryptoPlotTests(unittest.TestCase):
    def test_detects_result_type_from_directory_name(self) -> None:
        self.assertEqual(
            detect_benchmark_type(Path("cert_device_20260719_123")),
            "certificate",
        )
        self.assertEqual(
            detect_benchmark_type(Path("kem_device_20260719_123")),
            "kem",
        )
        with self.assertRaises(ValueError):
            detect_benchmark_type(Path("other_20260719_123"))

    def test_certificate_aggregation_uses_device_heap_and_seconds(self) -> None:
        attempts = [
            {
                "cert_sig_alg": "ML-DSA-44",
                "sig_family": "pqc",
                "sig_nist_level": "2",
                "status": "success",
                "certificate_total_ms": "2000",
                "certificate_keygen_ms": "500",
                "certificate_make_body_ms": "100",
                "certificate_sign_ms": "900",
                "certificate_verify_ms": "500",
                "certificate_der_bytes": "1500",
                "client_heap_peak_bytes": "4096",
            },
            {
                "cert_sig_alg": "ML-DSA-44",
                "sig_family": "pqc",
                "sig_nist_level": "2",
                "status": "success",
                "certificate_total_ms": "4000",
                "certificate_keygen_ms": "1000",
                "certificate_make_body_ms": "200",
                "certificate_sign_ms": "1800",
                "certificate_verify_ms": "1000",
                "certificate_der_bytes": "1500",
                "client_heap_peak_bytes": "6144",
            },
        ]
        row = aggregate_certificate_rows(attempts)[0]
        self.assertAlmostEqual(row["mean_time_seconds"], 3.0)
        self.assertAlmostEqual(row["peak_memory_kb"], 6.0)
        self.assertEqual(row["generated_output_bytes"], 1500)
        self.assertAlmostEqual(row["sign_seconds"], 1.35)

    def test_kem_output_sums_public_ciphertext_and_shared_secret(self) -> None:
        attempts = [
            {
                "kex_group": "MLKEM512",
                "kex_family": "pqc",
                "kex_nist_level": "1",
                "operation_model": "kem",
                "status": "success",
                "kem_total_ms": "100",
                "kem_keygen_ms": "20",
                "kem_encapsulation_ms": "30",
                "kem_decapsulation_ms": "50",
                "kex_public_key_bytes": "800",
                "kex_ciphertext_bytes": "768",
                "kex_shared_secret_bytes": "32",
                "client_heap_peak_bytes": "5120",
            }
        ]
        row = aggregate_kem_rows(attempts)[0]
        self.assertAlmostEqual(row["mean_time_seconds"], 0.1)
        self.assertAlmostEqual(row["peak_memory_kb"], 5.0)
        self.assertEqual(row["generated_output_bytes"], 1600)

    def test_latex_table_contains_individual_operations_and_failures(self) -> None:
        rows = [
            {
                "algorithm": "MLKEM_512",
                "nist_level": "1",
                "keygen_seconds": 0.1,
                "encapsulation_seconds": 0.2,
                "decapsulation_seconds": 0.3,
                "mean_time_seconds": 0.6,
                "peak_memory_kb": 5.0,
                "generated_output_bytes": 1600,
                "success_count": 5,
                "attempt_count": 5,
                "status": "success",
            },
            {
                "algorithm": "FAILED_KEM",
                "nist_level": "5",
                "keygen_seconds": None,
                "encapsulation_seconds": None,
                "decapsulation_seconds": None,
                "mean_time_seconds": None,
                "peak_memory_kb": None,
                "generated_output_bytes": None,
                "success_count": 0,
                "attempt_count": 5,
                "status": "no_success",
            },
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "table.tex"
            write_latex_table(
                rows,
                benchmark_type="kem",
                run_id="kem_device_test",
                output=output,
            )
            text = output.read_text()
        self.assertIn("KeyGen (s)", text)
        self.assertIn("Encaps (s)", text)
        self.assertIn("Decaps (s)", text)
        self.assertIn(r"MLKEM\_512", text)
        self.assertIn(r"\caption{On-device kem benchmark}", text)
        self.assertNotIn("benchmark: kem", text)
        self.assertIn("0.10 & 0.20 & 0.30 & 0.60", text)
        self.assertIn("1600.00", text)
        self.assertIn("0/5", text)
        self.assertIn("--", text)


if __name__ == "__main__":
    unittest.main()
