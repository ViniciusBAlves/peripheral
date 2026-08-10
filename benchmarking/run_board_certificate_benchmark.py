#!/usr/bin/env python3
"""Run the board-side wolfSSL client certificate generation benchmark."""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import time
from datetime import datetime
from pathlib import Path

from benchmarklib.algorithms import SIGNATURES_BY_NAME, slug
from benchmarklib.firmware import build as build_firmware
from benchmarklib.firmware import flash as flash_firmware
from run_benchmarks import (
    DEFAULT_CONFIG,
    DEFAULT_NCS_VERSION,
    default_ncs_chdir,
    default_nrfutil,
    load_config,
    resolve_serial_device,
)


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
WORK = ROOT / "work"
SLOW_SIGNATURE_TIMEOUT_SEC = 2000.0
SIGNATURE_TIMEOUTS_SEC = {
    "RSA-PSS-3072": 2400.0,
    "RSA-PSS-7680": 43200.0,
    "RSA-PSS-15360": 604800.0,
    "SLH-DSA-SHAKE-128s": 2400.0,
    "SLH-DSA-SHAKE-128f": 2400.0,
    "SLH-DSA-SHAKE-192s": 4200.0,
    "SLH-DSA-SHAKE-192f": 4200.0,
    "SLH-DSA-SHAKE-256s": 4200.0,
    "SLH-DSA-SHAKE-256f": 4200.0,
}
PHASES = [
    "keygen", "make_cert", "sign_cert", "parse_cert", "key_export",
]
PHASE_THREAD_BUCKETS = ["main", "sysworkq", "bt_rx", "bt_tx", "idle", "other"]
PHASE_DWT_METRICS = [
    ("core", "cycles"), ("lsu", "cycles"), ("cpi", "cycles"),
    ("exc", "cycles"), ("sleep", "cycles"), ("fold", "events"),
]
LEGACY_PHASE_DWT_METRICS = [("lsu", "cycles"), ("cpi", "cycles")]
ADDED_PHASE_DWT_METRICS = [
    metric for metric in PHASE_DWT_METRICS
    if metric not in LEGACY_PHASE_DWT_METRICS
]

ATTEMPT_FIELDS = [
    "attempt_index", "component", "owner", "cert_sig_alg", "builder",
    "generation_scope", "status", "wall_ms", "client_cpu_ms",
    "client_cpu_cycles", "client_cycle_hz", "client_cpu_usage_percent",
    "system_cpu_usage_percent", "thread_main_cpu_percent",
    "thread_sysworkq_cpu_percent", "thread_bt_rx_cpu_percent",
    "thread_bt_tx_cpu_percent", "thread_idle_cpu_percent",
    "thread_other_cpu_percent", "keygen_cpu_ms", "make_cert_cpu_ms",
    "sign_cert_cpu_ms", "parse_cert_cpu_ms", "key_export_cpu_ms",
    "phase_cpu_total_ms", "phase_cpu_verify",
    *[f"{phase}_wall_ms" for phase in PHASES],
    *[
        f"{phase}_thread_{bucket}_cpu_percent"
        for bucket in PHASE_THREAD_BUCKETS
        for phase in PHASES
    ],
    *[f"{phase}_heap_current_bytes" for phase in PHASES],
    *[f"{phase}_heap_peak_bytes" for phase in PHASES],
    *[f"{phase}_lsu_cycles" for phase in PHASES],
    "phase_lsu_total_cycles",
    *[f"{phase}_cpi_cycles" for phase in PHASES],
    "phase_cpi_total_cycles",
    "phase_dwt_samples", "dwt_counters_supported", "dwt_wrap_risk",
    "client_heap_current_bytes",
    "client_heap_peak_bytes", "client_heap_free_bytes",
    "client_heap_capacity_bytes", "thread_stack_used_bytes",
    "thread_stack_capacity_bytes", "thread_stack_peak_percent",
    "client_cert_der_bytes", "client_key_der_bytes",
    "client_cert_der_capacity_bytes", "client_key_der_capacity_bytes",
    "client_hbs_state_capacity_bytes", "error_code",
    "message",
    *[
        f"{phase}_{counter}_{suffix}"
        for counter, suffix in ADDED_PHASE_DWT_METRICS
        for phase in PHASES
    ],
    *[
        f"phase_{counter}_total_{suffix}"
        for counter, suffix in ADDED_PHASE_DWT_METRICS
    ],
    "firmware_static_ram_used_bytes",
    "firmware_ram_capacity_bytes", "firmware_static_ram_usage_percent",
]

SUMMARY_FIELDS = [
    "component", "owner", "cert_sig_alg", "builder", "generation_scope",
    "status", "success_count", "fail_count", "mean_wall_ms",
    "mean_client_cpu_ms", "mean_keygen_cpu_ms", "mean_make_cert_cpu_ms",
    "mean_thread_main_cpu_percent", "mean_thread_sysworkq_cpu_percent",
    "mean_thread_bt_rx_cpu_percent", "mean_thread_bt_tx_cpu_percent",
    "mean_thread_idle_cpu_percent", "mean_thread_other_cpu_percent",
    "mean_sign_cert_cpu_ms", "mean_parse_cert_cpu_ms",
    "mean_key_export_cpu_ms", "mean_phase_cpu_total_ms",
    *[f"mean_{phase}_wall_ms" for phase in PHASES],
    *[
        f"mean_{phase}_thread_{bucket}_cpu_percent"
        for bucket in PHASE_THREAD_BUCKETS
        for phase in PHASES
    ],
    *[f"max_{phase}_heap_peak_bytes" for phase in PHASES],
    *[f"mean_{phase}_lsu_cycles" for phase in PHASES],
    *[f"mean_{phase}_cpi_cycles" for phase in PHASES],
    "phase_cpu_verify", "mean_phase_lsu_total_cycles",
    "mean_phase_cpi_total_cycles", "max_phase_dwt_samples",
    "dwt_counters_supported", "dwt_wrap_risk", "max_client_heap_peak_bytes",
    "max_thread_stack_peak_percent", "client_cert_der_bytes",
    "client_key_der_bytes",
    *[
        f"mean_{phase}_{counter}_{suffix}"
        for counter, suffix in ADDED_PHASE_DWT_METRICS
        for phase in PHASES
    ],
    *[
        f"mean_phase_{counter}_total_{suffix}"
        for counter, suffix in ADDED_PHASE_DWT_METRICS
    ],
    "firmware_static_ram_used_bytes", "firmware_ram_capacity_bytes",
    "firmware_static_ram_usage_percent",
]


def write_csv(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def parse_key_values(line: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for token in line.strip().split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        values[key] = value
    return values


def bp_to_percent(value: str | None) -> str:
    if not value:
        return ""
    try:
        return f"{int(value) / 100.0:.2f}"
    except ValueError:
        return ""


def us_to_ms(value: str | None) -> str:
    if not value:
        return ""
    try:
        return f"{int(value) / 1000.0:.3f}"
    except ValueError:
        return ""


def usage_percent(values: dict[str, str], used_key: str, capacity_key: str) -> str:
    try:
        used = float(values.get(used_key, ""))
        capacity = float(values.get(capacity_key, ""))
    except ValueError:
        return ""
    if capacity <= 0:
        return ""
    return f"{100.0 * used / capacity:.2f}"


def wait_for_certgen_result(
    serial_port,
    log: Path,
    timeout_sec: float,
) -> dict[str, str]:
    deadline = time.monotonic() + timeout_sec
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a") as stream:
        while time.monotonic() < deadline:
            raw = serial_port.readline()
            if not raw:
                continue
            line = raw.decode(errors="replace").strip()
            stream.write(line + "\n")
            stream.flush()
            if line.startswith("[BENCH_CERTGEN_RESULT]"):
                return parse_key_values(
                    line.removeprefix("[BENCH_CERTGEN_RESULT]").strip()
                )
    raise TimeoutError(f"timed out waiting for BENCH_CERTGEN_RESULT after {timeout_sec}s")


def attempt_row(values: dict[str, str]) -> dict[str, object]:
    status = values.get("status", "fail")
    row = {
        "attempt_index": 1,
        "component": "client_certificate",
        "owner": "client",
        "cert_sig_alg": values.get("algorithm", "ECDSA-P-256"),
        "builder": values.get("builder", "wolfssl_board"),
        "generation_scope": values.get("generation_scope", "client_self_signed_cert"),
        "status": status,
        "wall_ms": values.get("wall_ms", ""),
        "client_cpu_ms": us_to_ms(values.get("client_cpu_us")),
        "client_cpu_cycles": values.get("client_cpu_cycles", ""),
        "client_cycle_hz": values.get("client_cycle_hz", ""),
        "client_cpu_usage_percent": bp_to_percent(values.get("client_cpu_usage_bp")),
        "system_cpu_usage_percent": bp_to_percent(values.get("system_cpu_usage_bp")),
        "thread_main_cpu_percent": bp_to_percent(values.get("thread_main_cpu_bp")),
        "thread_sysworkq_cpu_percent": bp_to_percent(
            values.get("thread_sysworkq_cpu_bp")
        ),
        "thread_bt_rx_cpu_percent": bp_to_percent(values.get("thread_bt_rx_cpu_bp")),
        "thread_bt_tx_cpu_percent": bp_to_percent(values.get("thread_bt_tx_cpu_bp")),
        "thread_idle_cpu_percent": bp_to_percent(values.get("thread_idle_cpu_bp")),
        "thread_other_cpu_percent": bp_to_percent(values.get("thread_other_cpu_bp")),
        "keygen_cpu_ms": us_to_ms(values.get("keygen_cpu_us")),
        "make_cert_cpu_ms": us_to_ms(values.get("make_cert_cpu_us")),
        "sign_cert_cpu_ms": us_to_ms(values.get("sign_cert_cpu_us")),
        "parse_cert_cpu_ms": us_to_ms(values.get("parse_cert_cpu_us")),
        "key_export_cpu_ms": us_to_ms(values.get("key_export_cpu_us")),
        "phase_cpu_total_ms": us_to_ms(values.get("phase_cpu_total_us")),
        "phase_cpu_verify": values.get("phase_cpu_verify", ""),
        "phase_dwt_samples": values.get("phase_dwt_samples", ""),
        "dwt_counters_supported": values.get("dwt_counters_supported", ""),
        "dwt_wrap_risk": values.get("dwt_wrap_risk", ""),
        "client_heap_current_bytes": values.get("client_heap_current_bytes", ""),
        "client_heap_peak_bytes": values.get("client_heap_peak_bytes", ""),
        "client_heap_free_bytes": values.get("client_heap_free_bytes", ""),
        "client_heap_capacity_bytes": values.get("client_heap_capacity_bytes", ""),
        "firmware_static_ram_used_bytes": values.get(
            "firmware_static_ram_used_bytes", ""
        ),
        "firmware_ram_capacity_bytes": values.get("firmware_ram_capacity_bytes", ""),
        "firmware_static_ram_usage_percent": usage_percent(
            values, "firmware_static_ram_used_bytes", "firmware_ram_capacity_bytes"
        ),
        "thread_stack_used_bytes": values.get("thread_stack_used_bytes", ""),
        "thread_stack_capacity_bytes": values.get("thread_stack_capacity_bytes", ""),
        "thread_stack_peak_percent": bp_to_percent(
            values.get("thread_stack_peak_percent_bp")
        ),
        "client_cert_der_bytes": values.get("client_cert_der_bytes", ""),
        "client_key_der_bytes": values.get("client_key_der_bytes", ""),
        "client_cert_der_capacity_bytes": values.get(
            "client_cert_der_capacity_bytes", ""
        ),
        "client_key_der_capacity_bytes": values.get(
            "client_key_der_capacity_bytes", ""
        ),
        "client_hbs_state_capacity_bytes": values.get(
            "client_hbs_state_capacity_bytes", ""
        ),
        "error_code": values.get("error", ""),
        "message": "" if status == "success" else values.get("stage", ""),
    }
    for counter, suffix in PHASE_DWT_METRICS:
        row[f"phase_{counter}_total_{suffix}"] = values.get(
            f"phase_{counter}_total_{suffix}", ""
        )
        for phase in PHASES:
            row[f"{phase}_{counter}_{suffix}"] = values.get(
                f"{phase}_{counter}_{suffix}", ""
            )
    for phase in PHASES:
        row[f"{phase}_wall_ms"] = values.get(f"{phase}_wall_ms", "")
        row[f"{phase}_heap_current_bytes"] = values.get(
            f"{phase}_heap_current_bytes", ""
        )
        row[f"{phase}_heap_peak_bytes"] = values.get(f"{phase}_heap_peak_bytes", "")
        for bucket in PHASE_THREAD_BUCKETS:
            row[f"{phase}_thread_{bucket}_cpu_percent"] = bp_to_percent(
                values.get(f"{phase}_thread_{bucket}_cpu_bp")
            )
    return row


def unsupported_row(signature: str, message: str) -> dict[str, object]:
    return {
        "attempt_index": 1,
        "component": "client_certificate",
        "owner": "client",
        "cert_sig_alg": signature,
        "builder": "wolfssl_board",
        "generation_scope": "client_self_signed_cert",
        "status": "unsupported",
        "message": message,
    }


def serial_timeout_for(signature: str, requested: float) -> float:
    if signature in SIGNATURE_TIMEOUTS_SEC:
        return max(requested, SIGNATURE_TIMEOUTS_SEC[signature])
    if signature.startswith(("RSA-PSS-", "SLH-DSA-SHAKE-")) or signature in {
        "LMS-HSS-L2-H10-W4",
        "XMSS-SHA2_20_256",
    }:
        return max(requested, SLOW_SIGNATURE_TIMEOUT_SEC)
    return requested


def summarize(row: dict[str, object]) -> list[dict[str, object]]:
    success = row["status"] == "success"
    summary = {
        "component": row["component"],
        "owner": row["owner"],
        "cert_sig_alg": row["cert_sig_alg"],
        "builder": row["builder"],
        "generation_scope": row["generation_scope"],
        "status": row["status"],
        "success_count": 1 if success else 0,
        "fail_count": 0 if success else 1,
        "mean_wall_ms": row["wall_ms"] if success else "",
        "mean_client_cpu_ms": row["client_cpu_ms"] if success else "",
        "mean_thread_main_cpu_percent": (
            row["thread_main_cpu_percent"] if success else ""
        ),
        "mean_thread_sysworkq_cpu_percent": (
            row["thread_sysworkq_cpu_percent"] if success else ""
        ),
        "mean_thread_bt_rx_cpu_percent": (
            row["thread_bt_rx_cpu_percent"] if success else ""
        ),
        "mean_thread_bt_tx_cpu_percent": (
            row["thread_bt_tx_cpu_percent"] if success else ""
        ),
        "mean_thread_idle_cpu_percent": (
            row["thread_idle_cpu_percent"] if success else ""
        ),
        "mean_thread_other_cpu_percent": (
            row["thread_other_cpu_percent"] if success else ""
        ),
        "mean_keygen_cpu_ms": row["keygen_cpu_ms"] if success else "",
        "mean_make_cert_cpu_ms": row["make_cert_cpu_ms"] if success else "",
        "mean_sign_cert_cpu_ms": row["sign_cert_cpu_ms"] if success else "",
        "mean_parse_cert_cpu_ms": row["parse_cert_cpu_ms"] if success else "",
        "mean_key_export_cpu_ms": row["key_export_cpu_ms"] if success else "",
        "mean_phase_cpu_total_ms": row["phase_cpu_total_ms"] if success else "",
        "phase_cpu_verify": row["phase_cpu_verify"] if success else "",
        "max_phase_dwt_samples": row["phase_dwt_samples"] if success else "",
        "dwt_counters_supported": row["dwt_counters_supported"] if success else "",
        "dwt_wrap_risk": row["dwt_wrap_risk"] if success else "",
        "max_client_heap_peak_bytes": row["client_heap_peak_bytes"] if success else "",
        "firmware_static_ram_used_bytes": (
            row["firmware_static_ram_used_bytes"] if success else ""
        ),
        "firmware_ram_capacity_bytes": (
            row["firmware_ram_capacity_bytes"] if success else ""
        ),
        "firmware_static_ram_usage_percent": (
            row["firmware_static_ram_usage_percent"] if success else ""
        ),
        "max_thread_stack_peak_percent": (
            row["thread_stack_peak_percent"] if success else ""
        ),
        "client_cert_der_bytes": row["client_cert_der_bytes"] if success else "",
        "client_key_der_bytes": row["client_key_der_bytes"] if success else "",
    }
    for counter, suffix in PHASE_DWT_METRICS:
        summary[f"mean_phase_{counter}_total_{suffix}"] = (
            row[f"phase_{counter}_total_{suffix}"] if success else ""
        )
    for phase in PHASES:
        summary[f"mean_{phase}_wall_ms"] = row[f"{phase}_wall_ms"] if success else ""
        summary[f"max_{phase}_heap_peak_bytes"] = (
            row[f"{phase}_heap_peak_bytes"] if success else ""
        )
        for counter, suffix in PHASE_DWT_METRICS:
            summary[f"mean_{phase}_{counter}_{suffix}"] = (
                row[f"{phase}_{counter}_{suffix}"] if success else ""
            )
        for bucket in PHASE_THREAD_BUCKETS:
            summary[f"mean_{phase}_thread_{bucket}_cpu_percent"] = (
                row[f"{phase}_thread_{bucket}_cpu_percent"] if success else ""
            )
    return [summary]


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    config_args, _ = config_parser.parse_known_args(argv)
    config = load_config(config_args.config)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=config_args.config)
    parser.add_argument("--run-id")
    parser.add_argument("--signature", default="ECDSA-P-256")
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-flash", action="store_true")
    parser.add_argument("--serial-device", default=config["serial-device"])
    parser.add_argument("--serial-baud", type=int, default=115200)
    parser.add_argument("--serial-timeout-sec", type=float, default=30.0)
    parser.add_argument("--nrfutil", default=default_nrfutil())
    parser.add_argument("--ncs-version", default=DEFAULT_NCS_VERSION)
    parser.add_argument("--ncs-chdir", default=default_ncs_chdir())
    parser.add_argument("--board", default="nrf52840dk/nrf52840")
    args = parser.parse_args(argv)
    args.serial_device = resolve_serial_device(args.serial_device)
    return args


def write_certgen_placeholder_credentials(output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "#ifndef BENCHMARK_CREDENTIALS_H\n"
        "#define BENCHMARK_CREDENTIALS_H\n\n"
        "#include <stddef.h>\n\n"
        "static const unsigned char benchmark_client_cert[] = { 0x00 };\n"
        "static const unsigned char benchmark_client_key[] = { 0x00 };\n"
        "static const unsigned char benchmark_server_root[] = { 0x00 };\n\n"
        "struct benchmark_ca_entry { const unsigned char *data; size_t length; };\n"
        "static const struct benchmark_ca_entry benchmark_ca_bundle[] = {\n"
        "    { benchmark_server_root, sizeof(benchmark_server_root) }\n"
        "};\n"
        "#define BENCHMARK_CA_COUNT "
        "(sizeof(benchmark_ca_bundle) / sizeof(benchmark_ca_bundle[0]))\n"
        "#endif\n"
    )


def run_board_client_certificate_benchmark(
    args: argparse.Namespace,
    *,
    run_id: str,
    run_dir: Path,
    signature: str | None = None,
) -> dict[str, object]:
    signature = signature or getattr(args, "signature", "ECDSA-P-256")
    if signature not in SIGNATURES_BY_NAME:
        return unsupported_row(signature, "unknown signature")

    signature_slug = slug(signature)
    generated_dir = WORK / "generated" / "board-certgen" / signature_slug
    write_certgen_placeholder_credentials(generated_dir / "benchmark_credentials.h")

    build_dir = WORK / "firmware-build" / f"client-certgen-{signature_slug}"
    if not args.skip_build:
        print(f"[firmware] Building/updating board certgen profile={signature}...", flush=True)
        build_firmware(
            firmware_dir=ROOT / "firmware",
            build_dir=build_dir,
            generated_dir=generated_dir,
            log=run_dir / "build.log",
            nrfutil=args.nrfutil,
            ncs_version=args.ncs_version,
            ncs_chdir=args.ncs_chdir,
            board=args.board,
            mlkem_backend="wolfssl",
            pqm4_dir=None,
            extra_cmake_args=[
                "-DBENCH_CLIENT_CERTGEN=ON",
                f"-DBENCH_CLIENT_CERTGEN_SIG={signature}",
            ],
        )
        print("[firmware] Build completed.", flush=True)
    if not args.skip_flash:
        print(f"[firmware] Flashing board certgen profile={signature}...", flush=True)
        flash_firmware(
            build_dir=build_dir,
            log=run_dir / "flash.log",
            nrfutil=args.nrfutil,
            ncs_version=args.ncs_version,
            ncs_chdir=args.ncs_chdir,
        )
        print("[firmware] Flash completed.", flush=True)

    try:
        import serial
    except ImportError as error:
        raise RuntimeError("pyserial is required: python -m pip install pyserial") from error

    with serial.Serial(args.serial_device, args.serial_baud, timeout=0.25) as port:
        port.reset_input_buffer()
        values = wait_for_certgen_result(
            port,
            run_dir / "board-certgen.log",
            serial_timeout_for(signature, args.serial_timeout_sec),
        )

    row = attempt_row(values)
    shutil.copy2(
        generated_dir / "benchmark_credentials.h",
        run_dir / f"benchmark_credentials_client_{signature}.h",
    )
    return row


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    run_id = args.run_id or f"board_certgen_{datetime.now():%Y%m%d_%H%M%S}"
    run_dir = RESULTS / run_id
    if run_dir.exists():
        raise FileExistsError(f"refusing to overwrite {run_dir}")
    run_dir.mkdir(parents=True)

    row = run_board_client_certificate_benchmark(
        args,
        run_id=run_id,
        run_dir=run_dir,
        signature=args.signature,
    )
    write_csv(run_dir / "attempts.csv", ATTEMPT_FIELDS, [row])
    write_csv(run_dir / "summary.csv", SUMMARY_FIELDS, summarize(row))
    config = {
        key: str(value) if isinstance(value, Path) else value
        for key, value in vars(args).items()
    }
    (run_dir / "run_config.json").write_text(json.dumps(config, indent=2) + "\n")
    print(f"status={row['status']}")
    print(f"results={run_dir}")
    return 0 if row["status"] == "success" else 1


if __name__ == "__main__":
    raise SystemExit(main())
