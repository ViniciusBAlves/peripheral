from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from benchmarklib.metrics import parse_bench_line
from benchmarklib.algorithms import (
    PKI_CHAINS, SIGNATURES_BY_NAME, normalize_signature_scheme, slug,
)
from benchmarklib.power_profiler import PowerProfilerCapture, PowerProfilerSession
from benchmarklib.transfer import TransferOperation, TransferRound
from benchmarklib.certificates import (
    generate_universal_header,
    materialize_case,
    write_case_configs,
)
from benchmarklib.gateway import PiGateway
from benchmarklib.firmware import flash_usage
from benchmarklib.scheduler import build_jobs
from benchmarklib.server_backends import server_backend_for_case
from generate_cases import build_cases
from run_benchmarks import (
    ATTEMPT_FIELDS,
    client_kex_metric_keys,
    classify_gateway_start_failure,
    load_config,
    latest_benchmark_observation,
    normalize_ble_addr,
    group_jobs_by_firmware_profile,
    pack_root_profiles,
    parse_args,
    needs_large_rsa_firmware,
    resolve_pi_workdir,
    resolve_power_profiler_device,
    resolve_serial_device,
    read_checkpoint,
    run_job,
    summarize,
    transfer_rows_for_round,
    timeout_for_case,
    wait_for_result,
    wait_for_ble_result,
    write_checkpoint,
    firmware_cache_key,
)


class BenchmarkTests(unittest.TestCase):
    def test_latest_handshake_is_recovered_from_gateway_log(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            log = Path(tmpdir) / "gateway.log"
            log.write_text(
                "[BENCH_HANDSHAKE] status=success certificate_verify_alg=first\n"
                "[BENCH_RESULT] status=success stage=transfer_complete\n"
                "[BENCH_HANDSHAKE] status=success certificate_verify_alg=second\n"
            )
            values = latest_benchmark_observation(log, "HANDSHAKE")
            self.assertIsNotNone(values)
            self.assertEqual(values["certificate_verify_alg"], "second")

    def test_firmware_cache_key_tracks_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            firmware = root / "firmware"
            firmware.mkdir()
            source = firmware / "main.c"
            source.write_text("int main(void) { return 0; }\n")
            header = root / "credentials.h"
            header.write_text("static const int credential = 1;\n")
            options = {"board": "nrf52840dk_nrf52840"}

            first = firmware_cache_key(firmware, header, build_options=options)
            self.assertEqual(
                first,
                firmware_cache_key(firmware, header, build_options=options),
            )
            header.write_text("static const int credential = 2;\n")
            self.assertNotEqual(
                first,
                firmware_cache_key(firmware, header, build_options=options),
            )

    def test_materialized_case_shares_public_files_not_private_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            template = root / "template"
            destination = root / "case"
            template.mkdir()
            (template / "server.crt").write_text("certificate")
            (template / "server.key").write_text("private")
            (template / "mosquitto.conf").write_text("configuration")

            materialize_case(template, destination)

            self.assertTrue(os.path.samefile(
                template / "server.crt", destination / "server.crt",
            ))
            self.assertFalse(os.path.samefile(
                template / "server.key", destination / "server.key",
            ))
            (destination / "mosquitto.conf").write_text("changed")
            self.assertEqual(
                (template / "mosquitto.conf").read_text(), "configuration",
            )

    def test_truncated_transfer_sequence_is_ignored(self) -> None:
        job = TransferRound(
            sequence=1,
            case_id="case-a",
            round_index=1,
            operations=(TransferOperation(
                order=1,
                iteration=1,
                direction="device_to_server",
                payload_bytes=16 * 1024,
                payload_seed=123,
            ),),
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            rows = transfer_rows_for_round(
                job,
                [("TRANSFER_TRANSPORT", {"sequence": ""})],
                Path(tmpdir) / "broker.log",
                attempt_index=1,
                reconnect_count=0,
                round_status="fail",
            )
        self.assertEqual(rows[0]["status"], "not_run")

    def test_signature_schemes_are_exact_tls13_values(self) -> None:
        expected = {
            "ECDSA-P-256": ("ecdsa_secp256r1_sha256", 0x0403),
            "RSA-PSS-3072": ("rsa_pss_rsae_sha256", 0x0804),
            "ML-DSA-44": ("mldsa44", 0x0904),
            "SLH-DSA-SHAKE-256s": ("ecdsa_secp521r1_sha512", 0x0603),
            "SLH-DSA-SHAKE-128f": ("ecdsa_secp256r1_sha256", 0x0403),
            "SLH-DSA-SHAKE-192f": ("ecdsa_secp384r1_sha384", 0x0503),
            "SLH-DSA-SHAKE-256f": ("ecdsa_secp521r1_sha512", 0x0603),
            "LMS-HSS-L2-H10-W4": ("ecdsa_secp256r1_sha256", 0x0403),
            "XMSS-SHA2_20_256": ("ecdsa_secp256r1_sha256", 0x0403),
        }
        for name, (scheme, scheme_id) in expected.items():
            with self.subTest(name=name):
                signature = SIGNATURES_BY_NAME[name]
                self.assertEqual(signature.tls_signature_scheme, scheme)
                self.assertEqual(signature.tls_signature_scheme_id, scheme_id)

    def test_legacy_certificate_verify_label_is_normalized(self) -> None:
        self.assertEqual(
            normalize_signature_scheme("ECDSA-P-256", "SLH-DSA-SHAKE-128s"),
            "ecdsa_secp256r1_sha256",
        )

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

    def test_hash_based_roots_are_generated_as_three_tier_cases(self) -> None:
        cases = build_cases(1, 0, True)
        signatures = {
            case["root_sig_alg"]: case
            for case in cases
            if case["root_sig_alg"] in {"LMS-HSS-L2-H10-W4", "XMSS-SHA2_20_256"}
        }
        self.assertEqual(set(signatures), {"LMS-HSS-L2-H10-W4", "XMSS-SHA2_20_256"})
        self.assertTrue(all(
            case["expected_support"] == "required"
            for case in signatures.values()
        ))
        self.assertTrue(all(case["intermediate_sig_alg"] == case["leaf_sig_alg"]
                            for case in signatures.values()))

    def test_generator_has_28_chains_and_252_cases(self) -> None:
        self.assertEqual(len(PKI_CHAINS), 28)
        self.assertEqual(len(build_cases(1, 0, False)), 252)

    def test_generator_can_add_heavy_homogeneous_x509_chains(self) -> None:
        cases = build_cases(1, 0, False, True)
        chains = {
            case["pki_chain_id"]: case
            for case in cases
            if case["kex_group"] == "ECDHE-P-256"
        }
        self.assertEqual(len(chains), 39)
        for name in (
            "SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128f",
            "SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192f",
            "SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256f",
            "RSA-PSS-3072", "RSA-PSS-7680", "RSA-PSS-15360",
            "LMS-HSS-L2-H10-W4", "XMSS-SHA2_20_256",
        ):
            case = chains[f"homogeneous_{slug(name)}"]
            self.assertEqual(case["pki_kind"], "homogeneous_x509")
            self.assertEqual(case["root_sig_alg"], name)
            self.assertEqual(case["intermediate_sig_alg"], name)
            self.assertEqual(case["leaf_sig_alg"], name)

    def test_root_profiles_are_packed_largest_first(self) -> None:
        profiles = pack_root_profiles({"large": 8, "medium": 6, "small": 4}, 10)
        self.assertEqual(profiles, [{"large"}, {"medium", "small"}])

    def test_multiple_firmware_profiles_are_contiguous_and_seeded(self) -> None:
        cases = build_cases(1, 0, False)[:4]
        case_map = {case["case_id"]: case for case in cases}
        for index, case in enumerate(cases):
            case["firmware_profile"] = f"profile-{index % 2}"
        jobs = build_jobs(cases, seed=123, sessions_per_case=2)
        first = group_jobs_by_firmware_profile(jobs, case_map, 123)
        second = group_jobs_by_firmware_profile(jobs, case_map, 123)
        self.assertEqual(first, second)
        profiles = [case_map[job.case_id]["firmware_profile"] for job in first]
        transitions = sum(a != b for a, b in zip(profiles, profiles[1:]))
        self.assertEqual(transitions, 1)

    def test_flash_usage_reads_zephyr_map_symbols(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            map_path = Path(tmpdir) / "zephyr" / "zephyr.map"
            map_path.parent.mkdir()
            map_path.write_text(
                "FLASH 0x00000000 0x00100000 xr\n"
                " 0x000f0000 _flash_used = expression\n"
            )
            self.assertEqual(flash_usage(Path(tmpdir)), (0xF0000, 0x100000))

    def test_slh_dsa_fast_variants_are_generated_as_cases(self) -> None:
        cases = build_cases(1, 0, False)
        variants = {
            case["root_sig_alg"]
            for case in cases
            if case["root_sig_alg"].endswith("f")
        }
        self.assertEqual(
            variants,
            {
                "SLH-DSA-SHAKE-128f",
                "SLH-DSA-SHAKE-192f",
                "SLH-DSA-SHAKE-256f",
            },
        )

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

        powered = parse_args(["--cases", "cases.csv", "--power-profiler"])
        self.assertTrue(powered.power_profiler)
        self.assertEqual(powered.board, "nrf52840dk/nrf52840")

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
        capture._process_sample(1, 100.0, 0xe0)
        capture._process_sample(2, 100.0, 0xd0)
        capture._process_sample(3, 100.0, 0)
        capture._sample_index = 4
        values = capture._measurements()
        self.assertEqual(values["power_status"], "success")
        self.assertEqual(values["total_execution_duration_ms"], "0.020")
        self.assertEqual(values["total_execution_charge_uc"], "0.002000")
        self.assertEqual(values["total_execution_energy_uj"], "0.006000")

    def test_ppk2_session_uses_source_mode_and_turns_power_off(self) -> None:
        ppk = Mock()
        ppk.ser = Mock()
        ppk.get_modifiers.return_value = {"calibrated": True}
        with patch("benchmarklib.power_profiler._open_ppk", return_value=ppk):
            session = PowerProfilerSession("/dev/ppk2", 3000, 100)
            session.open()
            self.assertFalse(session.powered)
            session.power_on(boot_seconds=0)
            self.assertTrue(session.powered)
            session.power_cycle(off_seconds=0, boot_seconds=0)
            session.close()

        ppk.use_source_meter.assert_called_once_with()
        ppk.set_source_voltage.assert_called_once_with(3000)
        self.assertEqual(
            [call.args[0] for call in ppk.toggle_DUT_power.call_args_list],
            ["OFF", "ON", "OFF", "ON", "OFF"],
        )

    def test_ppk2_open_failure_leaves_source_off(self) -> None:
        ppk = Mock()
        ppk.ser = Mock()
        ppk.get_modifiers.return_value = {}
        with patch("benchmarklib.power_profiler._open_ppk", return_value=ppk):
            session = PowerProfilerSession("/dev/ppk2", 3000, 100)
            with self.assertRaises(RuntimeError):
                session.open()

        self.assertEqual(
            [call.args[0] for call in ppk.toggle_DUT_power.call_args_list],
            ["OFF", "OFF"],
        )
        ppk.ser.close.assert_called_once_with()
        self.assertIsNone(session.ppk)

    def test_ble_result_is_parsed_without_serial(self) -> None:
        gateway = Mock()
        gateway.remote_benchmark_result.return_value = (
            "[BENCH_RESULT] status=success raw_handshake_ms=123"
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            result = wait_for_ble_result(
                gateway, "case", Path(tmpdir) / "board.log", timeout=1.0
            )
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["raw_handshake_ms"], "123")

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
        self.assertEqual(values["mlkem_duration_ms"], "0.010")
        self.assertEqual(values["mlkem_energy_uj"], "0.012000")
        self.assertNotIn("classical_kex_energy_uj", values)
        self.assertEqual(values["handshake_duration_ms"], "0.070")
        self.assertEqual(values["total_execution_duration_ms"], "0.070")

    def test_power_windows_separate_mlkem_and_classical_kex(self) -> None:
        capture = PowerProfilerCapture("/dev/null", 3000, 100)
        masks = (0x00, 0xc0, 0xe0, 0xc0, 0xf0, 0xc0, 0xd0, 0xc0, 0x00)
        for index, mask in enumerate(masks):
            capture._process_sample(index, 100.0, mask)
        capture._sample_index = len(masks)

        values = capture._measurements()

        self.assertEqual(values["power_status"], "success")
        self.assertEqual(values["client_kem_duration_ms"], "0.020")
        self.assertEqual(values["mlkem_duration_ms"], "0.010")
        self.assertEqual(values["classical_kex_duration_ms"], "0.010")
        self.assertEqual(values["client_signature_duration_ms"], "0.010")

    def test_transfer_power_windows_follow_handshake_window(self) -> None:
        capture = PowerProfilerCapture(
            "/dev/null", 3000, 100, transfer_mode=True
        )
        masks = (
            0x00,
            0xc0, 0xe0, 0xc0, 0xd0, 0xc0, 0x00,
            0x80, 0x80, 0x00,
            0x80, 0x80, 0x80, 0x00,
        )
        for index, mask in enumerate(masks):
            capture._process_sample(index, 100.0, mask)
        capture._sample_index = len(masks)

        values = capture._measurements()

        self.assertEqual(values["power_status"], "success")
        self.assertEqual(values["total_execution_duration_ms"], "0.050")
        self.assertEqual(values["handshake_duration_ms"], "0.050")
        self.assertEqual(
            [window["duration_ms"] for window in values["transfer_power_windows"]],
            ["0.020", "0.030"],
        )
        self.assertEqual(
            [window["energy_uj"] for window in values["transfer_power_windows"]],
            ["0.006000", "0.009000"],
        )

    def test_power_windows_use_only_last_complete_execution(self) -> None:
        capture = PowerProfilerCapture("/dev/null", 3000, 100)
        masks = (0x00, 0xe0, 0xd0, 0x00, 0x00, 0xe0, 0xd0, 0x00)
        for index, mask in enumerate(masks):
            capture._process_sample(index, 100.0, mask)
        capture._sample_index = len(masks)

        values = capture._measurements()

        self.assertEqual(values["power_status"], "success")
        self.assertEqual(values["power_profiler_window_count"], 2)
        self.assertEqual(values["total_execution_duration_ms"], "0.020")
        self.assertEqual(values["client_kem_duration_ms"], "0.010")
        self.assertEqual(values["client_signature_duration_ms"], "0.010")

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

    def test_wait_for_result_fails_fast_on_board_mpu_fault(self) -> None:
        class FaultSerial:
            def readline(self) -> bytes:
                return b"***** MPU FAULT *****\n"

        with tempfile.TemporaryDirectory() as tmpdir:
            result = wait_for_result(
                FaultSerial(), Path(tmpdir) / "board.log", timeout=30.0
            )

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["stage"], "board_fatal")
        self.assertEqual(result["error"], "zephyr_fatal_error")
        self.assertEqual(result["fatal"], "1")

    def test_wait_for_result_detects_reboot_after_transfer_activity(self) -> None:
        class RebootingSerial:
            def __init__(self) -> None:
                self.lines = iter((
                    b"[BENCH_TRANSFER_RESULT] sequence=1 status=fail error=-5\n",
                    b"*** Booting nRF Connect SDK v3.3.0 ***\n",
                ))

            def readline(self) -> bytes:
                return next(self.lines, b"")

        observations: list[tuple[str, dict[str, str]]] = []
        with tempfile.TemporaryDirectory() as tmpdir:
            result = wait_for_result(
                RebootingSerial(), Path(tmpdir) / "board.log", timeout=30.0,
                observations=observations,
            )

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["stage"], "board_reboot")
        self.assertEqual(result["error"], "reboot_before_result")

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

    def test_openssl_server_restricts_server_signature_algorithm(self) -> None:
        case = {
            "kex_group": "ECDHE-P-521",
            "cert_sig_alg": "ECDSA-P-521",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir)
            write_case_configs(case, output)
            openssl_config = (output / "openssl.cnf").read_text()

        self.assertIn("Groups = P-521\n", openssl_config)
        self.assertIn(
            "SignatureAlgorithms = ecdsa_secp521r1_sha512\n",
            openssl_config,
        )
        self.assertNotIn("ClientSignatureAlgorithms", openssl_config)
        self.assertNotIn("MaxSendFragment", openssl_config)

    def test_mosquitto_is_server_authentication_only(self) -> None:
        case = {
            "kex_group": "ECDHE-P-256",
            "cert_sig_alg": "ECDSA-P-256",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir)
            write_case_configs(case, output)
            server_only = (output / "mosquitto.conf").read_text()

        self.assertIn("require_certificate false\n", server_only)
        self.assertNotIn("cafile ", server_only)
        self.assertFalse((output / "mosquitto-mtls.conf").exists())

    def test_mosquitto_mtls_requires_client_certificate(self) -> None:
        case = {
            "kex_group": "ECDHE-P-256",
            "cert_sig_alg": "ECDSA-P-256",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir)
            (output / "client_ca.crt").write_text("test CA")
            write_case_configs(case, output)
            config = (output / "mosquitto-mtls.conf").read_text()
            openssl_config = (output / "openssl-mtls.cnf").read_text()

        self.assertIn("require_certificate true\n", config)
        self.assertIn("cafile __REMOTE_CASE_DIR__/client_ca.crt\n", config)
        self.assertIn(
            "ClientSignatureAlgorithms = ecdsa_secp256r1_sha256\n",
            openssl_config,
        )

    def test_universal_bundle_uses_explicit_pki_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            case_dir = root / "custom-case-id"
            case_dir.mkdir()
            write_case_configs(
                {
                    "kex_group": "ECDHE-P-256",
                    "cert_sig_alg": "ECDSA-P-256",
                },
                case_dir,
            )
            (case_dir / "server_root.der").write_bytes(b"root")
            (case_dir / "pki_metadata.json").write_text(
                '{"root_sig_alg":"ECDSA-P-256","leaf_sig_alg":"ECDSA-P-256"}'
            )
            output = root / "benchmark_credentials.h"
            generate_universal_header([("custom-case-id", case_dir)], output)
            header = output.read_text()

        self.assertIn('"ECDSA-P-256", "ecdsa_secp256r1_sha256"', header)
        self.assertIn("0x0403", header)

    def test_slh_openssl_server_uses_smaller_tls_records(self) -> None:
        case = {
            "kex_group": "ECDHE-P-521",
            "cert_sig_alg": "ECDSA-P-521",
            "root_sig_alg": "SLH-DSA-SHAKE-256s",
            "leaf_sig_alg": "ECDSA-P-521",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir)
            write_case_configs(case, output)
            openssl_config = (output / "openssl.cnf").read_text()

        self.assertIn("Groups = P-521\n", openssl_config)
        self.assertIn("MaxSendFragment = 2048\n", openssl_config)

    def test_server_backend_policy_routes_hash_based_signatures(self) -> None:
        classic = {"cert_sig_alg": "ECDSA-P-256"}
        lms = {"cert_sig_alg": "ECDSA-P-521", "root_sig_alg": "LMS-HSS-L2-H10-W4"}
        xmss = {"cert_sig_alg": "ECDSA-P-521", "root_sig_alg": "XMSS-SHA2_20_256"}
        slh = {"cert_sig_alg": "SLH-DSA-SHAKE-256s"}
        rsa_7680 = {"cert_sig_alg": "RSA-PSS-7680"}
        rsa_15360 = {"cert_sig_alg": "RSA-PSS-15360"}

        self.assertEqual(
            server_backend_for_case(classic, "auto"), "openssl-mosquitto"
        )
        self.assertEqual(server_backend_for_case(lms, "auto"), "wolfssl")
        self.assertEqual(server_backend_for_case(xmss, "auto"), "wolfssl")
        self.assertEqual(server_backend_for_case(rsa_7680, "auto"), "wolfssl")
        self.assertEqual(server_backend_for_case(rsa_15360, "auto"), "wolfssl")
        self.assertEqual(server_backend_for_case(slh, "auto"), "openssl-mosquitto")
        self.assertEqual(server_backend_for_case(classic, "wolfssl"), "wolfssl")
        self.assertEqual(
            server_backend_for_case(classic, "openssl-mosquitto"),
            "openssl-mosquitto",
        )
        self.assertIsNone(server_backend_for_case(lms, "openssl-mosquitto"))
        self.assertIsNone(server_backend_for_case(xmss, "openssl-mosquitto"))
        homogeneous_lms = {"cert_sig_alg": "LMS-HSS-L2-H10-W4"}
        self.assertEqual(server_backend_for_case(homogeneous_lms, "auto"), "wolfssl")
        self.assertIsNone(
            server_backend_for_case(homogeneous_lms, "openssl-mosquitto")
        )
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
            "average_cpu_usage_percent": "88.00",
            "peak_cpu_usage_percent": "99.00",
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
        self.assertEqual(summary["mean_average_cpu_usage_percent"], "88.000")
        self.assertEqual(summary["max_peak_cpu_usage_percent"], "99.000")
        self.assertEqual(summary["mean_client_icache_hits"], "900.000")
        self.assertEqual(summary["mean_client_icache_hit_percent"], "90.0000")
        self.assertEqual(
            summary["client_memory_access_counters_supported"], "0"
        )
        self.assertEqual(summary["firmware_flash_used_bytes"], "600000")
        self.assertEqual(summary["max_thread_stack_peak_percent"], "72.50")

    def test_all_handshakes_are_capped_at_sixty_seconds(self) -> None:
        classic = {"kex_group": "ECDHE-P-256", "cert_sig_alg": "ECDSA-P-256"}
        hybrid = {
            "kex_group": "X25519MLKEM768",
            "cert_sig_alg": "SLH-DSA-SHAKE-256s",
        }
        self.assertEqual(timeout_for_case(classic, None), 60.0)
        self.assertEqual(timeout_for_case(hybrid, None), 60.0)
        self.assertEqual(
            timeout_for_case({"kex_group": "ECDHE-P-256", "cert_sig_alg": "LMS-HSS-L2-H10-W4"}, None),
            60.0,
        )
        self.assertEqual(
            timeout_for_case({"kex_group": "ECDHE-P-256", "cert_sig_alg": "XMSS-SHA2_20_256"}, None),
            60.0,
        )
        self.assertEqual(timeout_for_case(hybrid, 12.0), 12.0)
        self.assertEqual(
            timeout_for_case(
                {"kex_group": "ECDHE-P-256", "cert_sig_alg": "RSA-PSS-7680"},
                None,
            ),
            60.0,
        )
        self.assertEqual(
            timeout_for_case(
                {"kex_group": "ECDHE-P-256", "cert_sig_alg": "RSA-PSS-15360"},
                None,
            ),
            60.0,
        )
        self.assertEqual(timeout_for_case(classic, 600.0), 60.0)

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
                control_telemetry=True,
            )
        launch = next(command for command in gateway.commands if "--name PQC52840" in command)
        self.assertNotIn("--forget-cache", launch)
        self.assertNotIn("--addr ", launch)
        self.assertNotIn("--disable-wifi", launch)
        self.assertIn("--name PQC52840", launch)
        readiness = next(
            command for command in gateway.commands
            if "gateway_tcp_connect_ms" in command
        )
        self.assertIn("BENCH_READY", readiness)

        gateway.set_wifi_enabled(False, Path(tmp) / "gateway.log")
        self.assertIn("nmcli radio wifi off", gateway.commands[-1])

    def test_gateway_selects_root_and_leaf_for_both_server_backends(self) -> None:
        class FakeGateway(PiGateway):
            def __init__(self) -> None:
                super().__init__("pi", "/remote")
                self.commands: list[str] = []

            def command(self, script, log, *, check=True):  # type: ignore[no-untyped-def]
                self.commands.append(script)
                return None

        common = {
            "case_id": "case",
            "remote_case_dir": "/remote/cases/case",
            "ble_addr": "",
            "ble_name": "PQC5340",
            "ble_addr_type": "random",
            "psm": "0x0080",
            "mtu": 672,
            "adapter": "hci0",
            "disable_wifi": False,
            "ready_timeout": 1,
            "log": Path("/tmp/gateway.log"),
            "root_signature": "SLH-DSA-SHAKE-128s",
            "leaf_signature": "ECDSA-P-256",
            "signature_scheme": "ecdsa_secp256r1_sha256",
        }
        mosquitto = FakeGateway()
        mosquitto.start_session(**common)
        self.assertTrue(any(
            "mosquitto.conf" in command and
            "--root-signature SLH-DSA-SHAKE-128s" in command and
            "--leaf-signature ECDSA-P-256" in command
            for command in mosquitto.commands
        ))

        wolfssl = FakeGateway()
        wolfssl.start_session(
            **common,
            server_backend="wolfssl",
            wolfssl_group="WOLFSSL_ECC_SECP256R1",
        )
        self.assertTrue(any(
            "wolfssl_tls_server" in command and "--mtls" not in command and
            "--sigalg ecdsa_secp256r1_sha256" in command
            for command in wolfssl.commands
        ))

        mtls = FakeGateway()
        mtls.start_session(**common, mtls_mode=True)
        self.assertTrue(any(
            "OPENSSL_CONF=/remote/cases/case/openssl-mtls.cnf" in command and
            "/remote/cases/case/mosquitto-mtls.conf" in command
            for command in mtls.commands
        ))

    def test_wolfssl_server_has_optional_mtls_path(self) -> None:
        source = (
            ROOT / "gateway" / "wolfssl_tls_server.c"
        ).read_text()
        self.assertIn('{ "mtls", no_argument', source)
        self.assertIn("WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT", source)
        self.assertIn("WOLFSSL_VERIFY_NONE", source)
        self.assertIn('strncmp(name, "mldsa", 5)', source)
        self.assertIn("sigalg_list[0] != '\\0'", source)

    def test_wolfssl_server_waits_for_board_shutdown_after_connack(self) -> None:
        source = (ROOT / "gateway" / "wolfssl_tls_server.c").read_text()
        self.assertIn("static void wait_for_client_shutdown", source)
        self.assertLess(
            source.index("wait_for_client_shutdown(ssl);"),
            source.index("(void)wolfSSL_shutdown(ssl);"),
        )

    def test_gateway_command_creates_log_parent(self) -> None:
        class TrueGateway(PiGateway):
            def ssh_base(self) -> list[str]:
                return ["true"]

        gateway = TrueGateway("pi", "/remote")
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "missing" / "gateway-control.log"
            gateway.command("ignored", log)
            self.assertTrue(log.exists())

    def test_gateway_master_retries_transient_route_failure(self) -> None:
        class RetryGateway(PiGateway):
            def __init__(self) -> None:
                super().__init__("pi", "/remote")
                self.calls = 0

            def _local(self, command, log):  # type: ignore[no-untyped-def]
                self.calls += 1
                if self.calls < 3:
                    raise RuntimeError("No route to host")

        gateway = RetryGateway()
        with tempfile.TemporaryDirectory() as tmp:
            gateway.start_master(
                Path(tmp) / "gateway.log", attempts=3, retry_delay=0
            )
        self.assertEqual(gateway.calls, 3)


if __name__ == "__main__":
    unittest.main()
