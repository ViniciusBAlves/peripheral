from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "graphic"))

from plot_certificate_summary import load_summary, sort_rows


class CertificateSummaryPlotTests(unittest.TestCase):
    def test_timeout_attempt_is_kept_and_sorted_last(self) -> None:
        fields = ["cert_sig_alg", "status", "mean_wall_ms", "sig_family"]
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            with (run_dir / "summary.csv").open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields)
                writer.writeheader()
                writer.writerow({
                    "cert_sig_alg": "ECDSA-P-256",
                    "status": "success",
                    "mean_wall_ms": "125",
                    "sig_family": "classic",
                })
                writer.writerow({
                    "cert_sig_alg": "SLH-DSA-SHAKE-256s",
                    "status": "fail",
                    "mean_wall_ms": "",
                    "sig_family": "pqc",
                })
            with (run_dir / "attempts.csv").open("w", newline="") as stream:
                writer = csv.DictWriter(
                    stream, fieldnames=["cert_sig_alg", "status"]
                )
                writer.writeheader()
                writer.writerow({
                    "cert_sig_alg": "SLH-DSA-SHAKE-256s",
                    "status": "timeout",
                })

            rows = sort_rows(load_summary(run_dir, include_failed=False))

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[-1]["cert_sig_alg"], "SLH-DSA-SHAKE-256s")
        self.assertEqual(rows[-1]["_plot_status"], "timeout")

    def test_unmeasured_failure_still_requires_include_failed(self) -> None:
        fields = ["cert_sig_alg", "status", "mean_wall_ms"]
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            with (run_dir / "summary.csv").open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=fields)
                writer.writeheader()
                writer.writerow({
                    "cert_sig_alg": "BROKEN",
                    "status": "fail",
                    "mean_wall_ms": "",
                })
            with self.assertRaises(ValueError):
                load_summary(run_dir, include_failed=False)


if __name__ == "__main__":
    unittest.main()
