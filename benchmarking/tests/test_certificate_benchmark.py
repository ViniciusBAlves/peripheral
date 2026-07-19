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


if __name__ == "__main__":
    unittest.main()
