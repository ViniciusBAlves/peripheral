#!/usr/bin/env python3
"""Benchmark KEM key generation, encapsulation and decapsulation on the DK."""

from __future__ import annotations

import argparse
import csv
import json
import random
import shutil
import statistics
import time
from datetime import datetime
from pathlib import Path

from benchmarklib.algorithms import KEMS_BY_NAME, Kem, slug
from benchmarklib.firmware import build as build_firmware
from benchmarklib.firmware import ensure_pqm4
from benchmarklib.firmware import flash as flash_firmware
from benchmarklib.firmware import reset as reset_firmware


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
WORK = ROOT / "work"
MAX_ALGORITHM_TIMEOUT_SEC = 15 * 60

PRIVATE_KEY_BYTES = {
    "ECDHE-P-256": 32,
    "ECDHE-P-384": 48,
    "ECDHE-P-521": 66,
    "MLKEM512": 1632,
    "MLKEM768": 2400,
    "MLKEM1024": 3168,
    "SecP256r1MLKEM768": 2432,
    "X25519MLKEM768": 2432,
    "SecP384r1MLKEM1024": 3216,
}

ATTEMPT_FIELDS = [
    "attempt_index", "component", "owner", "kex_group", "kex_family",
    "kex_nist_level", "kex_public_key_bytes", "kex_private_key_bytes",
    "kex_ciphertext_bytes", "kex_shared_secret_bytes", "mlkem_backend",
    "operation_model", "status", "wall_ms", "cpu_ms",
    "kem_keygen_ms", "kem_encapsulation_ms", "kem_decapsulation_ms",
    "kem_total_ms", "secrets_match", "client_cpu_cycles",
    "client_cycle_hz", "client_heap_current_bytes",
    "dwt_cycle_counter_supported", "dwt_event_counters_supported",
    "dwt_cyccnt", "dwt_cpicnt", "dwt_exccnt", "dwt_sleepcnt",
    "dwt_lsucnt", "dwt_foldcnt", "dwt_cycle_counter_width_bits",
    "dwt_event_counter_width_bits", "dwt_counts_are_modulo",
    "client_heap_peak_bytes", "client_heap_free_bytes",
    "client_heap_capacity_bytes", "error_code", "message",
]

SUMMARY_FIELDS = [
    "component", "owner", "kex_group", "kex_family", "kex_nist_level",
    "kex_public_key_bytes", "kex_private_key_bytes",
    "kex_ciphertext_bytes", "kex_shared_secret_bytes", "mlkem_backend",
    "operation_model", "status", "success_count", "fail_count",
    "timeout_count", "cancelled_count",
    "mean_kem_keygen_ms", "median_kem_keygen_ms", "p95_kem_keygen_ms",
    "stddev_kem_keygen_ms", "mean_kem_encapsulation_ms",
    "median_kem_encapsulation_ms", "p95_kem_encapsulation_ms",
    "stddev_kem_encapsulation_ms", "mean_kem_decapsulation_ms",
    "median_kem_decapsulation_ms", "p95_kem_decapsulation_ms",
    "stddev_kem_decapsulation_ms", "mean_kem_total_ms",
    "median_kem_total_ms", "p95_kem_total_ms", "stddev_kem_total_ms",
    "mean_cpu_ms", "max_client_heap_peak_bytes",
    "mean_dwt_cyccnt", "mean_dwt_cpicnt", "mean_dwt_exccnt",
    "mean_dwt_sleepcnt", "mean_dwt_lsucnt", "mean_dwt_foldcnt",
]


def write_csv(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def read_kem_cases(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as stream:
        reader = csv.DictReader(stream)
        if "kex_group" not in (reader.fieldnames or []):
            raise ValueError("case CSV is missing kex_group")
        rows = [
            dict(row) for row in reader
            if row.get("enabled", "").lower() in {"1", "true", "yes"}
        ]
    selected: dict[str, dict[str, str]] = {}
    for row in rows:
        group = row["kex_group"]
        if group not in KEMS_BY_NAME:
            raise ValueError(f"unknown KEM group: {group}")
        selected.setdefault(group, row)
    if not selected:
        raise ValueError("case CSV has no enabled KEM cases")
    return list(selected.values())


def parse_board_values(line: str, marker: str) -> dict[str, str] | None:
    if marker not in line:
        return None
    values: dict[str, str] = {}
    for token in line.split(marker, 1)[1].strip().split():
        if "=" in token:
            key, value = token.split("=", 1)
            values[key] = value
    return values


def wait_for_board_marker(
    serial_port, log: Path, marker: str, timeout: float
) -> dict[str, str]:
    deadline = time.monotonic() + timeout
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a") as stream:
        while time.monotonic() < deadline:
            raw = serial_port.readline()
            if not raw:
                continue
            line = raw.decode("utf-8", errors="replace").strip()
            stream.write(line + "\n")
            stream.flush()
            values = parse_board_values(line, marker)
            if values is not None:
                return values
    raise TimeoutError(f"board did not print {marker} within {timeout:g}s")


def microseconds_as_ms(values: dict[str, str], key: str) -> str:
    try:
        return f"{int(values[key]) / 1000.0:.3f}"
    except (KeyError, ValueError):
        return ""


def attempt_row(
    attempt: int, kem: Kem, values: dict[str, str]
) -> dict[str, object]:
    status = values.get("status", "fail").lower()
    expected_sizes = (
        kem.public_key_bytes,
        PRIVATE_KEY_BYTES[kem.name],
        kem.ciphertext_bytes,
        kem.shared_secret_bytes,
    )
    reported_sizes = tuple(
        int(values.get(field, "0") or 0)
        for field in (
            "kex_public_key_bytes", "kex_private_key_bytes",
            "kex_ciphertext_bytes", "kex_shared_secret_bytes",
        )
    )
    size_mismatch = status == "success" and reported_sizes != expected_sizes
    secret_mismatch = (
        status == "success" and values.get("secrets_match", "0") != "1"
    )
    if size_mismatch or secret_mismatch:
        status = "fail"
    cycle_hz = int(values.get("client_cycle_hz", "0") or 0)
    cycles = int(values.get("client_cpu_cycles", "0") or 0)
    cpu_ms = f"{cycles * 1000.0 / cycle_hz:.3f}" if cycle_hz else ""
    total_ms = microseconds_as_ms(values, "kem_total_us")
    error = (
        "metadata_mismatch" if size_mismatch else
        "shared_secret_mismatch" if secret_mismatch else
        values.get("error", "")
    )
    return {
        "attempt_index": attempt,
        "component": "on_device_kem",
        "owner": "client",
        "kex_group": kem.name,
        "kex_family": kem.family,
        "kex_nist_level": kem.nist_level,
        "kex_public_key_bytes": values.get("kex_public_key_bytes", ""),
        "kex_private_key_bytes": values.get("kex_private_key_bytes", ""),
        "kex_ciphertext_bytes": values.get("kex_ciphertext_bytes", ""),
        "kex_shared_secret_bytes": values.get("kex_shared_secret_bytes", ""),
        "mlkem_backend": values.get("mlkem_backend", ""),
        "operation_model": values.get("operation_model", ""),
        "status": status,
        "wall_ms": total_ms,
        "cpu_ms": cpu_ms,
        "kem_keygen_ms": microseconds_as_ms(values, "kem_keygen_us"),
        "kem_encapsulation_ms": microseconds_as_ms(
            values, "kem_encapsulation_us"
        ),
        "kem_decapsulation_ms": microseconds_as_ms(
            values, "kem_decapsulation_us"
        ),
        "kem_total_ms": total_ms,
        "secrets_match": values.get("secrets_match", ""),
        "client_cpu_cycles": values.get("client_cpu_cycles", ""),
        "client_cycle_hz": values.get("client_cycle_hz", ""),
        **{
            field: values.get(field, "") for field in (
                "dwt_cycle_counter_supported", "dwt_event_counters_supported",
                "dwt_cyccnt", "dwt_cpicnt", "dwt_exccnt", "dwt_sleepcnt",
                "dwt_lsucnt", "dwt_foldcnt",
                "dwt_cycle_counter_width_bits",
                "dwt_event_counter_width_bits", "dwt_counts_are_modulo",
            )
        },
        "client_heap_current_bytes": values.get(
            "client_heap_current_bytes", ""
        ),
        "client_heap_peak_bytes": values.get("client_heap_peak_bytes", ""),
        "client_heap_free_bytes": values.get("client_heap_free_bytes", ""),
        "client_heap_capacity_bytes": values.get(
            "client_heap_capacity_bytes", ""
        ),
        "error_code": error,
        "message": (
            f"reported_sizes={reported_sizes},expected={expected_sizes}"
            if size_mismatch else
            "encapsulated and decapsulated secrets differ"
            if secret_mismatch else
            "" if status == "success" else values.get("stage", "")
        ),
    }


def percentile(values: list[float], percent: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * percent
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def distribution(values: list[float]) -> tuple[str, str, str, str]:
    if not values:
        return "", "", "", ""
    return (
        f"{statistics.mean(values):.3f}",
        f"{statistics.median(values):.3f}",
        f"{percentile(values, 0.95):.3f}",
        f"{statistics.stdev(values):.3f}" if len(values) > 1 else "0.000",
    )


def summarize(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    groups: dict[str, list[dict[str, object]]] = {}
    for row in rows:
        groups.setdefault(str(row["kex_group"]), []).append(row)
    summaries = []
    for group, items in sorted(groups.items()):
        success = [row for row in items if row["status"] == "success"]
        base = items[0]

        def numbers(field: str) -> list[float]:
            return [
                float(row[field]) for row in success
                if row.get(field, "") != ""
            ]

        keygen = distribution(numbers("kem_keygen_ms"))
        encaps = distribution(numbers("kem_encapsulation_ms"))
        decaps = distribution(numbers("kem_decapsulation_ms"))
        total = distribution(numbers("kem_total_ms"))
        cpu = numbers("cpu_ms")
        heap = numbers("client_heap_peak_bytes")
        dwt_values = {
            field: numbers(field)
            for field in (
                "dwt_cyccnt", "dwt_cpicnt", "dwt_exccnt",
                "dwt_sleepcnt", "dwt_lsucnt", "dwt_foldcnt",
            )
        }
        summaries.append({
            **{
                field: base.get(field, "") for field in (
                    "component", "owner", "kex_group", "kex_family",
                    "kex_nist_level", "kex_public_key_bytes",
                    "kex_private_key_bytes", "kex_ciphertext_bytes",
                    "kex_shared_secret_bytes", "mlkem_backend",
                    "operation_model",
                )
            },
            "status": "success" if len(success) == len(items) else "fail",
            "success_count": len(success),
            "fail_count": sum(row["status"] == "fail" for row in items),
            "timeout_count": sum(row["status"] == "timeout" for row in items),
            "cancelled_count": sum(
                row["status"] == "cancelled" for row in items
            ),
            "mean_kem_keygen_ms": keygen[0],
            "median_kem_keygen_ms": keygen[1],
            "p95_kem_keygen_ms": keygen[2],
            "stddev_kem_keygen_ms": keygen[3],
            "mean_kem_encapsulation_ms": encaps[0],
            "median_kem_encapsulation_ms": encaps[1],
            "p95_kem_encapsulation_ms": encaps[2],
            "stddev_kem_encapsulation_ms": encaps[3],
            "mean_kem_decapsulation_ms": decaps[0],
            "median_kem_decapsulation_ms": decaps[1],
            "p95_kem_decapsulation_ms": decaps[2],
            "stddev_kem_decapsulation_ms": decaps[3],
            "mean_kem_total_ms": total[0],
            "median_kem_total_ms": total[1],
            "p95_kem_total_ms": total[2],
            "stddev_kem_total_ms": total[3],
            "mean_cpu_ms": f"{statistics.mean(cpu):.3f}" if cpu else "",
            "max_client_heap_peak_bytes": (
                f"{max(heap):.0f}" if heap else ""
            ),
            **{
                f"mean_{field}": (
                    f"{statistics.mean(values):.3f}" if values else ""
                )
                for field, values in dwt_values.items()
            },
        })
    return summaries


def default_nrfutil() -> str:
    return shutil.which("nrfutil") or str(Path.home() / ".local/bin/nrfutil")


def default_ncs_chdir() -> str:
    candidates = (
        Path.home() / "Documents/ncs/v3.3.0/nrf",
        Path.home() / "ncs/v3.3.0/nrf",
    )
    return str(next((path for path in candidates if path.exists()), candidates[0]))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument("--config", type=Path, default=ROOT / "config.json")
    config_args, _ = config_parser.parse_known_args(argv)
    config = json.loads(config_args.config.read_text())

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=config_args.config)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=5)
    parser.add_argument("--seed", type=int, default=123)
    parser.add_argument("--run-id")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--only-kem", action="append", default=[])
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-flash", action="store_true")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--mlkem-backend", choices=("pqm4-m4fstack", "wolfssl"),
        default="pqm4-m4fstack",
    )
    parser.add_argument(
        "--serial-device", default=config.get("serial-device", "/dev/ttyACM0")
    )
    parser.add_argument("--serial-baud", type=int, default=115200)
    parser.add_argument("--board-ready-timeout-sec", type=float, default=30.0)
    parser.add_argument(
        "--attempt-timeout-sec", type=float,
        default=MAX_ALGORITHM_TIMEOUT_SEC,
        help="per-attempt timeout, capped at 900 seconds",
    )
    parser.add_argument("--nrfutil", default=default_nrfutil())
    parser.add_argument("--ncs-version", default="v3.3.0")
    parser.add_argument("--ncs-chdir", default=default_ncs_chdir())
    parser.add_argument("--board", default="nrf5340dk/nrf5340/cpuapp")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.iterations < 1:
        raise ValueError("--iterations must be at least 1")
    if args.limit is not None and args.limit < 1:
        raise ValueError("--limit must be at least 1")
    if args.attempt_timeout_sec <= 0:
        raise ValueError("--attempt-timeout-sec must be positive")

    cases = read_kem_cases(args.cases)
    if args.only_kem:
        wanted = set(args.only_kem)
        cases = [case for case in cases if case["kex_group"] in wanted]
        missing = wanted - {case["kex_group"] for case in cases}
        if missing:
            raise ValueError(f"unknown or disabled KEMs: {', '.join(sorted(missing))}")
    random.Random(args.seed).shuffle(cases)
    if args.limit is not None:
        cases = cases[:args.limit]
    if not cases:
        raise ValueError("no KEMs selected")

    run_id = args.run_id or f"kem_device_{datetime.now():%Y%m%d_%H%M%S}_{args.seed}"
    run_dir = RESULTS / run_id
    if run_dir.exists():
        raise FileExistsError(f"refusing to overwrite {run_dir}")
    run_dir.mkdir(parents=True)
    shutil.copy2(args.cases, run_dir / "input_cases.csv")
    (run_dir / "seed.txt").write_text(f"{args.seed}\n")
    (run_dir / "run_config.json").write_text(json.dumps({
        "mode": "on-device-kem-operations",
        "board": args.board,
        "serial_device": args.serial_device,
        "iterations": args.iterations,
        "seed": args.seed,
        "mlkem_backend": args.mlkem_backend,
        "attempt_timeout_sec": min(
            args.attempt_timeout_sec, MAX_ALGORITHM_TIMEOUT_SEC
        ),
    }, indent=2) + "\n")
    write_csv(
        run_dir / "run_manifest.csv",
        ["sequence", "case_id", "kex_group", "seed", "run_id"],
        [
            {
                "sequence": sequence,
                "case_id": f"kembench__{slug(case['kex_group'])}",
                "kex_group": case["kex_group"],
                "seed": args.seed,
                "run_id": run_id,
            }
            for sequence, case in enumerate(cases, 1)
        ],
    )
    if args.dry_run:
        print(f"results={run_dir}")
        return 0

    pqm4_dir = None
    if args.mlkem_backend == "pqm4-m4fstack":
        pqm4_dir = WORK / "pqm4"
        print(f"[pqm4] preparing pinned sources -> {pqm4_dir}", flush=True)
        ensure_pqm4(pqm4_dir, run_dir / "build.log")

    build_dir = (
        WORK / "firmware-build" /
        f"kem-operations-nrf5340-{slug(args.mlkem_backend)}"
    )
    if args.skip_build and not (build_dir / "zephyr/zephyr.hex").exists():
        raise FileNotFoundError(
            f"--skip-build requested but {build_dir / 'zephyr/zephyr.hex'} "
            "does not exist"
        )
    if not args.skip_build:
        print(f"[build] KEM firmware -> {build_dir}", flush=True)
        build_firmware(
            firmware_dir=ROOT / "firmware",
            build_dir=build_dir,
            generated_dir=run_dir,
            log=run_dir / "build.log",
            nrfutil=args.nrfutil,
            ncs_version=args.ncs_version,
            ncs_chdir=args.ncs_chdir,
            board=args.board,
            mlkem_backend=args.mlkem_backend,
            pqm4_dir=pqm4_dir,
            kem_benchmark=True,
        )
    if not args.skip_flash:
        print("[flash] programming KEM firmware", flush=True)
        flash_firmware(
            build_dir=build_dir,
            log=run_dir / "flash.log",
            nrfutil=args.nrfutil,
            ncs_version=args.ncs_version,
            ncs_chdir=args.ncs_chdir,
        )

    try:
        import serial
    except ImportError as exc:
        raise RuntimeError("pyserial is required: python -m pip install pyserial") from exc
    if not hasattr(serial, "Serial"):
        raise RuntimeError(
            f"the imported serial module is not pyserial: {serial.__file__}"
        )

    attempts: list[dict[str, object]] = []
    board_log = run_dir / "board.log"
    with serial.Serial(
        args.serial_device, args.serial_baud, timeout=0.25
    ) as serial_port:
        serial_port.reset_input_buffer()
        if args.skip_flash:
            reset_firmware(log=run_dir / "flash.log", nrfutil=args.nrfutil)
        print(f"[board] waiting on {args.serial_device}", flush=True)
        wait_for_board_marker(
            serial_port, board_log, "[BENCH_READY]",
            args.board_ready_timeout_sec,
        )
        for sequence, case in enumerate(cases, 1):
            kem = KEMS_BY_NAME[case["kex_group"]]
            for attempt in range(1, args.iterations + 1):
                print(
                    f"[{sequence}/{len(cases)}] {kem.name} "
                    f"attempt={attempt}/{args.iterations}",
                    flush=True,
                )
                serial_port.write(
                    f"KEMBENCH kembench__{slug(kem.name)} "
                    f"{kem.name} {attempt}\n".encode()
                )
                serial_port.flush()
                timeout = min(
                    args.attempt_timeout_sec, MAX_ALGORITHM_TIMEOUT_SEC
                )
                try:
                    values = wait_for_board_marker(
                        serial_port, board_log, "[BENCH_KEM_RESULT]", timeout
                    )
                except TimeoutError:
                    values = {
                        "status": "timeout", "stage": "board_result",
                        "error": "timeout",
                    }
                    reset_firmware(
                        log=run_dir / "flash.log", nrfutil=args.nrfutil
                    )
                    wait_for_board_marker(
                        serial_port, board_log, "[BENCH_READY]",
                        args.board_ready_timeout_sec,
                    )
                attempts.append(attempt_row(attempt, kem, values))
                if values.get("status") == "timeout":
                    remaining = args.iterations - attempt
                    print(
                        f"  timeout after {timeout:g}s; cancelling "
                        f"{remaining} remaining {kem.name} iteration(s)",
                        flush=True,
                    )
                    for cancelled in range(attempt + 1, args.iterations + 1):
                        attempts.append(attempt_row(cancelled, kem, {
                            "status": "cancelled",
                            "stage": "cancelled_after_algorithm_timeout",
                            "error": "algorithm_timeout",
                        }))
                write_csv(run_dir / "attempts.csv", ATTEMPT_FIELDS, attempts)
                if values.get("status") == "timeout":
                    break

    write_csv(run_dir / "summary.csv", SUMMARY_FIELDS, summarize(attempts))
    print(f"results={run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
