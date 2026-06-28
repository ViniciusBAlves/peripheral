from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarklib.metrics import parse_bench_line
from benchmarklib.scheduler import build_jobs
from generate_cases import build_cases
from run_benchmarks import resolve_pi_workdir, timeout_for_case


class BenchmarkTests(unittest.TestCase):
    def test_schedule_is_reproducible(self) -> None:
        cases = build_cases(2, 1, True)[:2]
        first = build_jobs(cases, seed=123, sessions_per_case=2)
        second = build_jobs(cases, seed=123, sessions_per_case=2)
        self.assertEqual(first, second)
        self.assertNotEqual(first, build_jobs(cases, seed=124, sessions_per_case=2))

    def test_each_attempt_is_an_independent_job(self) -> None:
        cases = build_cases(2, 1, True)[:1]
        jobs = build_jobs(cases, seed=123, sessions_per_case=2)
        self.assertEqual(len(jobs), 6)
        self.assertEqual(sum(job.warmup for job in jobs), 2)

    def test_structured_metric_parser(self) -> None:
        parsed = parse_bench_line(
            "[BENCH_RESULT] status=success raw_handshake_ms=12.5 mqtt_connect_ms=3"
        )
        self.assertEqual(
            parsed,
            ("RESULT", {"status": "success", "raw_handshake_ms": "12.5",
                        "mqtt_connect_ms": "3"}),
        )

    def test_pi_workdir_follows_ssh_user(self) -> None:
        self.assertEqual(
            resolve_pi_workdir("thiago@10.12.194.1", ""),
            "/home/thiago/peripheral-benchmark",
        )

    def test_heavier_signatures_receive_longer_timeouts(self) -> None:
        classic = {"kex_group": "ECDHE-P-256", "cert_sig_alg": "ECDSA-P-256"}
        hybrid = {
            "kex_group": "X25519MLKEM768",
            "cert_sig_alg": "SLH-DSA-SHAKE-256s",
        }
        self.assertEqual(timeout_for_case(classic, None), 60.0)
        self.assertEqual(timeout_for_case(hybrid, None), 210.0)
        self.assertEqual(timeout_for_case(hybrid, 12.0), 12.0)


if __name__ == "__main__":
    unittest.main()
