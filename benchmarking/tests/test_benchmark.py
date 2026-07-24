from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarklib.metrics import parse_bench_line
from benchmarklib.power_profiler import PowerProfilerCapture
from benchmarklib.certificates import write_case_configs
from benchmarklib.gateway import PiGateway
from benchmarklib.scheduler import build_jobs
from benchmarklib.server_backends import server_backend_for_case
from generate_cases import build_cases
from run_benchmarks import (
    ATTEMPT_FIELDS,
    certificate_verify_profile,
    client_kex_metric_keys,
    classify_gateway_start_failure,
    load_config,
    normalize_ble_addr,
    parse_args,
    needs_large_rsa_firmware,
    resolve_pi_workdir,
    resolve_power_profiler_device,
    resolve_serial_device,
    read_checkpoint,
    run_job,
    summarize,
    timeout_for_case,
    wait_for_result,
    write_checkpoint,
)
import run_certificate_benchmarks as cert_bench
import run_board_certificate_benchmark as board_cert_bench


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

    def test_known_unsupported_cases_are_grouped_at_schedule_end(self) -> None:
        normal = {
            "case_id": "normal",
            "warmup_iterations": "1",
            "iterations": "2",
            "expected_support": "required",
        }
        unsupported = [
            {
                "case_id": f"unsupported_{index}",
                "warmup_iterations": "1",
                "iterations": "2",
                "expected_support": "known_unsupported",
            }
            for index in range(2)
        ]
        jobs = build_jobs(
            [normal, *unsupported], seed=123, sessions_per_case=2
        )
        normal_count = 2 * (
            int(normal["warmup_iterations"]) + int(normal["iterations"])
        )
        self.assertTrue(all(
            job.case_id == normal["case_id"] for job in jobs[:normal_count]
        ))
        deferred_ids = [job.case_id for job in jobs[normal_count:]]
        for case in unsupported:
            positions = [
                index for index, case_id in enumerate(deferred_ids)
                if case_id == case["case_id"]
            ]
            self.assertEqual(
                positions,
                list(range(min(positions), max(positions) + 1)),
            )

    def test_hash_based_signatures_are_generated_as_cases(self) -> None:
        cases = build_cases(1, 0, True)
        signatures = {
            case["cert_sig_alg"]: case
            for case in cases
            if case["cert_sig_alg"] in {"LMS-HSS-L2-H10-W4", "XMSS-SHA2_20_256"}
        }
        self.assertEqual(set(signatures), {"LMS-HSS-L2-H10-W4", "XMSS-SHA2_20_256"})
        self.assertTrue(all(
            case["expected_support"] == "required"
            for case in signatures.values()
        ))
        self.assertTrue(all(
            "CertificateVerify uses ECDSA" in case["notes"]
            for case in signatures.values()
        ))
        self.assertTrue(all(
            case["certificate_verify_alg"] == "ECDSA-P-256"
            for case in signatures.values()
        ))

    def test_certificate_verify_profile_uses_case_metadata(self) -> None:
        self.assertEqual(
            certificate_verify_profile({
                "cert_sig_alg": "ML-DSA-65",
                "certificate_verify_alg": "ML-DSA-65",
            }),
            "ML-DSA-65",
        )
        self.assertEqual(
            certificate_verify_profile({"cert_sig_alg": "ECDSA-P-256"}),
            "ECDSA-P-256",
        )

    def test_openssl_config_does_not_force_ecdsa_client_auth(self) -> None:
        case = {
            "kex_group": "ECDHE-P-256",
            "cert_sig_alg": "ML-DSA-65",
        }
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp)
            write_case_configs(case, output)
            config = (output / "openssl.cnf").read_text()
        self.assertNotIn("ClientSignatureAlgorithms = ECDSA+SHA256", config)

    def test_config_supplies_hardware_defaults_and_cli_overrides(self) -> None:
        config = load_config(ROOT / "config.json")
        args = parse_args(["--cases", "cases.csv"])
        self.assertEqual(
            args.serial_device,
            resolve_serial_device(config["serial-device"]),
        )
        self.assertEqual(args.pi_host, config["pi-host"])
        self.assertEqual(args.ble_addr, normalize_ble_addr(config["ble-addr"]))
        self.assertEqual(args.mlkem_backend, "pqm4-m4fstack")
        self.assertEqual(args.server_backend, "auto")
        self.assertFalse(args.power_profiler)
        self.assertEqual(
            args.power_profiler_output_samples_per_second,
            config["power-profiler-output-samples-per-second"],
        )

        overridden = parse_args([
            "--cases", "cases.csv", "--serial-device", "/dev/ttyUSB9",
            "--server-backend", "wolfssl",
        ])
        self.assertEqual(overridden.serial_device, "/dev/ttyUSB9")
        self.assertEqual(overridden.server_backend, "wolfssl")

    def test_old_config_gets_power_profiler_defaults(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "config.json"
            config_path.write_text(
                '{"serial-device":"/dev/board","pi-host":"user@pi",'
                '"ssh-key":"~/.ssh/key","ble-addr":"00:00:00:00:00:00"}'
            )
            config = load_config(config_path)
        self.assertEqual(config["power-profiler-serial-device"], "/dev/ttyACM0")
        self.assertEqual(config["power-profiler-vdd-mv"], 3000)
        self.assertEqual(config["power-profiler-output-samples-per-second"], 100)

    def test_power_windows_integrate_native_samples(self) -> None:
        capture = PowerProfilerCapture("/dev/null", 3000, 100)
        capture._process_sample(0, 100.0, 0)
        capture._process_sample(1, 100.0, 0xf0)
        capture._process_sample(2, 100.0, 0xf0)
        capture._process_sample(3, 100.0, 0)
        capture._sample_index = 4
        values = capture._measurements()
        self.assertEqual(values["power_status"], "success")
        self.assertEqual(values["total_execution_duration_ms"], "0.020")
        self.assertEqual(values["total_execution_charge_uc"], "0.002000")
        self.assertEqual(values["total_execution_energy_uj"], "0.006000")

    def test_power_windows_sum_all_crypto_pulses(self) -> None:
        capture = PowerProfilerCapture("/dev/null", 3000, 100)
        samples = (
            (0, 0x00),
            (100, 0xc0),
            (200, 0xd0),
            (300, 0xc0),
            (400, 0xe0),
            (500, 0xc0),
            (600, 0xd0),
            (700, 0xc0),
            (800, 0x00),
        )
        for index, (current_ua, mask) in enumerate(samples):
            capture._process_sample(index, float(current_ua), mask)
        capture._sample_index = len(samples)

        values = capture._measurements()

        self.assertEqual(values["power_status"], "success")
        self.assertEqual(values["client_signature_duration_ms"], "0.020")
        self.assertEqual(values["client_signature_charge_uc"], "0.008000")
        self.assertEqual(values["client_signature_energy_uj"], "0.024000")
        self.assertEqual(values["client_signature_peak_current_ua"], "600.000")
        self.assertEqual(values["client_kem_duration_ms"], "0.010")
        self.assertEqual(values["client_kem_energy_uj"], "0.012000")
        self.assertEqual(values["handshake_duration_ms"], "0.070")
        self.assertEqual(values["total_execution_duration_ms"], "0.070")

    def test_power_windows_use_only_last_complete_execution(self) -> None:
        capture = PowerProfilerCapture("/dev/null", 3000, 100)
        masks = (0x00, 0xf0, 0x00, 0x00, 0xf0, 0xf0, 0x00)
        for index, mask in enumerate(masks):
            capture._process_sample(index, 100.0, mask)
        capture._sample_index = len(masks)

        values = capture._measurements()

        self.assertEqual(values["power_status"], "success")
        self.assertEqual(values["power_profiler_window_count"], 2)
        self.assertEqual(values["total_execution_duration_ms"], "0.020")
        self.assertEqual(values["client_kem_duration_ms"], "0.020")
        self.assertEqual(values["client_signature_duration_ms"], "0.020")

    def test_distinct_existing_power_device_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            board = Path(tmpdir) / "board"
            power = Path(tmpdir) / "power"
            board.touch()
            power.touch()
            self.assertEqual(
                resolve_power_profiler_device(str(power), str(board)), str(power)
            )

    def test_resume_cli_does_not_require_cases(self) -> None:
        args = parse_args(["--resume", "run-123"])
        self.assertEqual(args.resume, "run-123")
        self.assertIsNone(args.cases)

    def test_checkpoint_advances_only_to_committed_execution(self) -> None:
        job = build_jobs(
            build_cases(1, 0, True)[:1],
            seed=123,
            sessions_per_case=1,
        )[0]
        with tempfile.TemporaryDirectory() as tmpdir:
            run_dir = Path(tmpdir)
            write_checkpoint(
                run_dir,
                execution_order=3,
                total_jobs=7,
                job=job,
            )
            checkpoint = read_checkpoint(run_dir)

        self.assertEqual(checkpoint["last_completed_execution_order"], 3)
        self.assertEqual(checkpoint["next_execution_order"], 4)
        self.assertEqual(checkpoint["case_id"], job.case_id)
        self.assertEqual(checkpoint["status"], "running")

    def test_placeholder_ble_addr_enables_name_discovery(self) -> None:
        self.assertEqual(normalize_ble_addr("00:00:00:00:00:00"), "")
        self.assertEqual(normalize_ble_addr("00.00.00.00.00"), "")
        self.assertEqual(normalize_ble_addr("000000000000"), "")
        self.assertEqual(
            normalize_ble_addr("F9:79:AE:2A:9A:1E"),
            "F9:79:AE:2A:9A:1E",
        )

    def test_gateway_start_failure_is_classified_from_bridge_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log = Path(tmpdir) / "gateway.log"
            log.write_text("[-] L2CAP Channel failed to open: timed out\n")
            final = {
                "status": "fail",
                "stage": "gateway_start",
                "error": "CalledProcessError",
            }
            classified = classify_gateway_start_failure(log, final)
        self.assertEqual(classified["stage"], "ble_l2cap_ready_timeout")

    def test_wait_for_result_fails_fast_on_fatal_server_log(self) -> None:
        class QuietSerial:
            def readline(self) -> bytes:
                return b""

        with tempfile.TemporaryDirectory() as tmpdir:
            result = wait_for_result(
                QuietSerial(),
                Path(tmpdir) / "board.log",
                timeout=30.0,
                fatal_detector=lambda: "OpenSSL Error[0]: tlsv1 alert unknown ca",
            )

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["stage"], "server_certificate_trust")
        self.assertEqual(result["error"], "fatal_server_log")
        self.assertEqual(result["fatal"], "1")
        self.assertIn("unknown ca", result["fatal_message"])

    def test_server_certificate_trust_failure_does_not_retry(self) -> None:
        class QuietSerial:
            name = "fake-serial"

            def reset_input_buffer(self) -> None:
                pass

            def readline(self) -> bytes:
                return b""

        class FakeGateway(PiGateway):
            def __init__(self) -> None:
                super().__init__("pi", "/remote")
                self.starts = 0
                self.workdir = "/remote"

            def start_session(self, **kwargs):  # type: ignore[no-untyped-def]
                self.starts += 1

            def stop_session(self, log, *, reset_adapter=False):  # type: ignore[no-untyped-def]
                pass

            def collect_session_logs(self, case_id, broker_log, gateway_log, log):  # type: ignore[no-untyped-def]
                broker_log.write_text("tlsv1 alert unknown ca\n")
                gateway_log.write_text("")

            def remote_file_contains(self, path, patterns):  # type: ignore[no-untyped-def]
                return "tlsv1 alert unknown ca"

        case = {
            "case_id": "ecdhe_p_256__ecdsa_p_256",
            "kex_group": "ECDHE-P-256",
            "kex_nist_level": "1",
            "kex_public_key_bytes": "65",
            "kex_ciphertext_bytes": "65",
            "kex_shared_secret_bytes": "32",
            "cert_sig_alg": "ECDSA-P-256",
            "sig_nist_level": "1",
            "sig_public_key_bytes": "65",
            "sig_private_key_bytes": "32",
            "sig_signature_bytes": "64",
            "certificate_verify_alg": "ECDSA-P-256",
        }
        args = type("Args", (), {
            "attempt_timeout_sec": 30.0,
            "reconnect_retries": 3,
            "reconnect_delay_sec": 0.0,
            "ble_addr": "",
            "ble_name": "PQC52840",
            "ble_addr_type": "random",
            "psm": "0x0080",
            "mtu": 672,
            "pi_adapter": "hci0",
            "disable_pi_wifi": True,
            "gateway_ready_timeout_sec": 1.0,
            "board_rearm_timeout_sec": 0.0,
        })()

        with tempfile.TemporaryDirectory() as tmpdir:
            gateway = FakeGateway()
            row = run_job(
                build_jobs([{**case, "warmup_iterations": "0", "iterations": "1"}],
                           seed=1, sessions_per_case=1)[0],
                case,
                Path(tmpdir),
                "/remote/cases/ecdhe_p_256__ecdsa_p_256",
                "openssl-mosquitto",
                gateway,
                QuietSerial(),
                args,
                attempt_index=1,
            )

        self.assertEqual(row["status"], "fail")
        self.assertEqual(row["reconnect_count"], 0)
        self.assertEqual(row["message"], "tlsv1 alert unknown ca")
        self.assertEqual(gateway.starts, 1)

    def test_openssl_server_does_not_force_board_client_signature_algorithm(self) -> None:
        case = {
            "kex_group": "ECDHE-P-521",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir)
            write_case_configs(case, output)
            openssl_config = (output / "openssl.cnf").read_text()

        self.assertIn("Groups = P-521\n", openssl_config)
        self.assertNotIn("ClientSignatureAlgorithms = ECDSA+SHA256\n", openssl_config)
        self.assertNotIn("MaxSendFragment", openssl_config)

    def test_slh_openssl_server_uses_smaller_tls_records(self) -> None:
        case = {
            "kex_group": "ECDHE-P-521",
            "cert_sig_alg": "SLH-DSA-SHAKE-256s",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir)
            write_case_configs(case, output)
            openssl_config = (output / "openssl.cnf").read_text()

        self.assertIn("Groups = P-521\n", openssl_config)
        self.assertIn("MaxSendFragment = 2048\n", openssl_config)

    def test_server_backend_policy_routes_hash_based_signatures(self) -> None:
        classic = {"cert_sig_alg": "ECDSA-P-256"}
        lms = {"cert_sig_alg": "LMS-HSS-L2-H10-W4"}
        xmss = {"cert_sig_alg": "XMSS-SHA2_20_256"}
        slh = {"cert_sig_alg": "SLH-DSA-SHAKE-256s"}

        self.assertEqual(
            server_backend_for_case(classic, "auto"), "openssl-mosquitto"
        )
        self.assertEqual(server_backend_for_case(lms, "auto"), "wolfssl")
        self.assertEqual(server_backend_for_case(xmss, "auto"), "wolfssl")
        self.assertEqual(server_backend_for_case(slh, "auto"), "openssl-mosquitto")
        self.assertEqual(server_backend_for_case(classic, "wolfssl"), "wolfssl")
        self.assertEqual(
            server_backend_for_case(classic, "openssl-mosquitto"),
            "openssl-mosquitto",
        )
        self.assertIsNone(server_backend_for_case(lms, "openssl-mosquitto"))
        self.assertIsNone(server_backend_for_case(xmss, "openssl-mosquitto"))
        self.assertEqual(
            server_backend_for_case(slh, "openssl-mosquitto"),
            "openssl-mosquitto",
        )

    def test_rsa_pss_uses_fast_math_firmware(self) -> None:
        self.assertFalse(needs_large_rsa_firmware({"cert_sig_alg": "RSA-PSS-3072"}))
        self.assertFalse(needs_large_rsa_firmware({"cert_sig_alg": "RSA-PSS-7680"}))
        self.assertFalse(needs_large_rsa_firmware({"cert_sig_alg": "RSA-PSS-15360"}))

    def test_structured_metric_parser(self) -> None:
        parsed = parse_bench_line(
            "[BENCH_RESULT] status=success raw_handshake_ms=12.5 mqtt_connect_ms=3"
        )
        self.assertEqual(
            parsed,
            ("RESULT", {"status": "success", "raw_handshake_ms": "12.5",
                        "mqtt_connect_ms": "3"}),
        )

    def test_client_kex_total_uses_only_selected_group_components(self) -> None:
        mlkem = {"kex_group": "MLKEM512"}
        hybrid = {"kex_group": "X25519MLKEM768"}
        classical = {"kex_group": "ECDHE-P-256"}
        self.assertNotIn(
            "classical_kex_keygen_us", client_kex_metric_keys(mlkem)
        )
        self.assertIn(
            "classical_kex_keygen_us", client_kex_metric_keys(hybrid)
        )
        self.assertNotIn("kem_keygen_us", client_kex_metric_keys(classical))

    def test_hardware_metrics_are_aggregated(self) -> None:
        case = build_cases(1, 0, True)[0]
        attempt = {field: "" for field in ATTEMPT_FIELDS}
        attempt.update({
            "warmup": 0,
            "status": "success",
            "raw_handshake_ms": "100",
            "client_cpu_ms": "40",
            "client_cpu_usage_percent": "40.00",
            "system_cpu_usage_percent": "55.00",
            "client_icache_hits": "900",
            "client_icache_misses": "100",
            "client_icache_requests": "1000",
            "client_icache_hit_percent": "90.0000",
            "client_icache_miss_percent": "10.0000",
            "client_memory_access_counters_supported": "0",
            "client_heap_peak_bytes": "4096",
            "firmware_flash_used_bytes": "600000",
            "firmware_flash_capacity_bytes": "1048576",
            "firmware_static_ram_used_bytes": "250000",
            "firmware_ram_capacity_bytes": "262144",
            "thread_stack_used_bytes": "5000",
            "thread_stack_capacity_bytes": "12000",
            "thread_stack_peak_percent": "72.50",
            "l2cap_tx_retries": "2",
            "l2cap_tx_wait_ms": "20.5",
            "l2cap_rx_overflows": "0",
        })
        summary = summarize(case, [attempt])
        self.assertEqual(summary["mean_client_cpu_usage_percent"], "40.000")
        self.assertEqual(summary["mean_system_cpu_usage_percent"], "55.000")
        self.assertEqual(summary["mean_client_icache_hits"], "900.000")
        self.assertEqual(summary["mean_client_icache_hit_percent"], "90.0000")
        self.assertEqual(
            summary["client_memory_access_counters_supported"], "0"
        )
        self.assertEqual(summary["firmware_flash_used_bytes"], "600000")
        self.assertEqual(summary["max_thread_stack_peak_percent"], "72.50")

    def test_certificate_summary_uses_board_cpu_metric(self) -> None:
        row = {field: "" for field in cert_bench.ATTEMPT_FIELDS}
        row.update({
            "attempt_index": 1,
            "component": "client_certificate",
            "owner": "client",
            "cert_sig_alg": "ECDSA-P-256",
            "sig_family": "classical",
            "sig_nist_level": 1,
            "builder": "wolfssl_board",
            "generation_scope": "client_self_signed_cert",
            "status": "success",
            "wall_ms": "80",
            "client_cpu_ms": "79.711",
            "keygen_cpu_ms": "12.000",
            "make_cert_cpu_ms": "3.000",
            "sign_cert_cpu_ms": "60.000",
            "parse_cert_cpu_ms": "1.000",
            "key_export_cpu_ms": "2.000",
            "phase_cpu_total_ms": "78.000",
            "phase_cpu_verify": "pass",
            "phase_lsu_total_cycles": "1234",
            "phase_cpi_total_cycles": "5678",
            "phase_dwt_samples": "90",
            "dwt_counters_supported": "1",
            "dwt_wrap_risk": "0",
        })

        summary = cert_bench.summarize([row])[0]

        self.assertEqual(summary["mean_cpu_ms"], "79.711")
        self.assertEqual(summary["mean_client_cpu_ms"], "79.711")
        self.assertEqual(summary["mean_keygen_cpu_ms"], "12.000")
        self.assertEqual(summary["mean_make_cert_cpu_ms"], "3.000")
        self.assertEqual(summary["mean_sign_cert_cpu_ms"], "60.000")
        self.assertEqual(summary["mean_parse_cert_cpu_ms"], "1.000")
        self.assertEqual(summary["mean_key_export_cpu_ms"], "2.000")
        self.assertEqual(summary["mean_phase_cpu_total_ms"], "78.000")
        self.assertEqual(summary["phase_cpu_verify"], "pass")
        self.assertEqual(summary["mean_phase_lsu_total_cycles"], "1234.000")
        self.assertEqual(summary["mean_phase_cpi_total_cycles"], "5678.000")
        self.assertEqual(summary["max_phase_dwt_samples"], "90")
        self.assertEqual(summary["dwt_counters_supported"], "1")
        self.assertEqual(summary["dwt_wrap_risk"], "0")

    def test_board_certificate_attempt_row_parses_phase_cpu_metrics(self) -> None:
        row = board_cert_bench.attempt_row({
            "status": "success",
            "algorithm": "ECDSA-P-256",
            "wall_ms": "80",
            "client_cpu_us": "79711",
            "keygen_cpu_us": "12000",
            "make_cert_cpu_us": "3000",
            "sign_cert_cpu_us": "60000",
            "parse_cert_cpu_us": "1000",
            "key_export_cpu_us": "2000",
            "phase_cpu_total_us": "78000",
            "phase_cpu_verify": "pass",
            "keygen_lsu_cycles": "100",
            "make_cert_lsu_cycles": "20",
            "sign_cert_lsu_cycles": "1000",
            "parse_cert_lsu_cycles": "30",
            "key_export_lsu_cycles": "84",
            "phase_lsu_total_cycles": "1234",
            "keygen_cpi_cycles": "500",
            "make_cert_cpi_cycles": "40",
            "sign_cert_cpi_cycles": "5000",
            "parse_cert_cpi_cycles": "50",
            "key_export_cpi_cycles": "88",
            "phase_cpi_total_cycles": "5678",
            "phase_dwt_samples": "90",
            "dwt_counters_supported": "1",
            "dwt_wrap_risk": "0",
        })

        self.assertEqual(row["client_cpu_ms"], "79.711")
        self.assertEqual(row["keygen_cpu_ms"], "12.000")
        self.assertEqual(row["make_cert_cpu_ms"], "3.000")
        self.assertEqual(row["sign_cert_cpu_ms"], "60.000")
        self.assertEqual(row["parse_cert_cpu_ms"], "1.000")
        self.assertEqual(row["key_export_cpu_ms"], "2.000")
        self.assertEqual(row["phase_cpu_total_ms"], "78.000")
        self.assertEqual(row["phase_cpu_verify"], "pass")
        self.assertEqual(row["phase_lsu_total_cycles"], "1234")
        self.assertEqual(row["phase_cpi_total_cycles"], "5678")
        self.assertEqual(row["phase_dwt_samples"], "90")
        self.assertEqual(row["dwt_counters_supported"], "1")
        self.assertEqual(row["dwt_wrap_risk"], "0")

    def test_heavier_signatures_receive_longer_timeouts(self) -> None:
        classic = {"kex_group": "ECDHE-P-256", "cert_sig_alg": "ECDSA-P-256"}
        hybrid = {
            "kex_group": "X25519MLKEM768",
            "cert_sig_alg": "SLH-DSA-SHAKE-256s",
        }
        self.assertEqual(timeout_for_case(classic, None), 60.0)
        self.assertEqual(timeout_for_case(hybrid, None), 210.0)
        self.assertEqual(
            timeout_for_case({"kex_group": "ECDHE-P-256", "cert_sig_alg": "LMS-HSS-L2-H10-W4"}, None),
            180.0,
        )
        self.assertEqual(
            timeout_for_case({"kex_group": "ECDHE-P-256", "cert_sig_alg": "XMSS-SHA2_20_256"}, None),
            210.0,
        )
        self.assertEqual(timeout_for_case(hybrid, 12.0), 12.0)

    def test_gateway_start_does_not_evict_bluez_cache(self) -> None:
        class FakeGateway(PiGateway):
            def __init__(self) -> None:
                super().__init__("pi", "/remote")
                self.commands: list[str] = []

            def command(self, script, log, *, check=True):  # type: ignore[no-untyped-def]
                self.commands.append(script)
                return None

        gateway = FakeGateway()
        with tempfile.TemporaryDirectory() as tmp:
            gateway.start_session(
                case_id="case",
                remote_case_dir="/remote/cases/case",
                ble_addr="",
                ble_name="PQC52840",
                ble_addr_type="random",
                psm="0x0080",
                mtu=672,
                adapter="hci0",
                disable_wifi=True,
                ready_timeout=1,
                log=Path(tmp) / "gateway.log",
            )
        launch = next(command for command in gateway.commands if "--name PQC52840" in command)
        self.assertNotIn("--forget-cache", launch)
        self.assertNotIn("--addr ", launch)
        self.assertIn("--disable-wifi", launch)
        self.assertIn("--name PQC52840", launch)

    def test_gateway_command_creates_log_parent(self) -> None:
        class TrueGateway(PiGateway):
            def ssh_base(self) -> list[str]:
                return ["true"]

        gateway = TrueGateway("pi", "/remote")
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "missing" / "gateway-control.log"
            gateway.command("ignored", log)
            self.assertTrue(log.exists())


if __name__ == "__main__":
    unittest.main()
