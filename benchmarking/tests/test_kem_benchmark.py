from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarklib.algorithms import KEMS_BY_NAME  # noqa: E402
from run_kem_benchmarks import attempt_row, read_kem_cases, summarize  # noqa: E402


class KemBenchmarkTests(unittest.TestCase):
    def test_case_reader_deduplicates_kem_groups(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "cases.csv"
            with path.open("w", newline="") as stream:
                writer = csv.DictWriter(stream, fieldnames=["enabled", "kex_group"])
                writer.writeheader()
                writer.writerow({"enabled": "1", "kex_group": "MLKEM512"})
                writer.writerow({"enabled": "1", "kex_group": "MLKEM512"})
            self.assertEqual(len(read_kem_cases(path)), 1)

    def test_success_requires_matching_sizes_and_secret(self) -> None:
        kem = KEMS_BY_NAME["MLKEM512"]
        values = {
            "status": "success",
            "kex_public_key_bytes": "800",
            "kex_private_key_bytes": "1632",
            "kex_ciphertext_bytes": "768",
            "kex_shared_secret_bytes": "32",
            "secrets_match": "1",
        }
        self.assertEqual(attempt_row(1, kem, values)["status"], "success")
        values["secrets_match"] = "0"
        row = attempt_row(1, kem, values)
        self.assertEqual(row["status"], "fail")
        self.assertEqual(row["error_code"], "shared_secret_mismatch")

    def test_summary_aggregates_each_operation(self) -> None:
        kem = KEMS_BY_NAME["MLKEM512"]
        rows = []
        for attempt, value in enumerate((10_000, 20_000, 30_000), 1):
            rows.append(attempt_row(attempt, kem, {
                "status": "success",
                "kex_public_key_bytes": "800",
                "kex_private_key_bytes": "1632",
                "kex_ciphertext_bytes": "768",
                "kex_shared_secret_bytes": "32",
                "secrets_match": "1",
                "kem_keygen_us": str(value),
                "kem_encapsulation_us": str(value),
                "kem_decapsulation_us": str(value),
                "kem_total_us": str(value * 3),
                "client_heap_peak_bytes": "4096",
                "client_heap_capacity_bytes": "8192",
                "firmware_static_ram_used_bytes": "65536",
                "firmware_ram_capacity_bytes": "262144",
            }))
        summary = summarize(rows)[0]
        self.assertEqual(summary["mean_kem_keygen_ms"], "20.000")
        self.assertEqual(summary["p95_kem_total_ms"], "87.000")
        self.assertEqual(summary["success_count"], 3)
        self.assertEqual(summary["max_client_heap_peak_usage_percent"], "50.00")
        self.assertEqual(summary["firmware_static_ram_usage_percent"], "25.00")


if __name__ == "__main__":
    unittest.main()
