#!/usr/bin/env python3
"""
Benchmark nRF52840 wolfSSL TLS 1.3 + PQC handshakes through a Raspberry Pi
BLE L2CAP -> Mosquitto bridge.

This harness intentionally assumes the lab topology that is now working:
  - client: nrf52840dk/nrf52840 on /dev/tty.usbmodem0010502058091
  - server/bridge: Raspberry Pi at vini@10.12.194.1
  - transport: BLE LE Credit Based L2CAP, PSM 0x0080
  - broker: Pi Mosquitto using OpenSSL 3.5 + oqs/OpenSSL PQC support

Docker is still used locally for certificate generation because it gives us a
known OpenSSL/PQC toolchain for ML-DSA and SLH-DSA certificates.
"""

from __future__ import annotations

import csv
import datetime as dt
import os
import re
import shlex
import shutil
import statistics
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
import serial


# ---------------------------------------------------------------------------
# Static lab configuration
# ---------------------------------------------------------------------------

PROJECT_DIR = Path(__file__).resolve().parent
SRC_DIR = PROJECT_DIR / "src"
BUILD_DIR = PROJECT_DIR / "build"
CERT_DIR = PROJECT_DIR / "generated_certs"
PI_DIR = PROJECT_DIR / "raspberry_pi"

BOARD = "nrf52840dk/nrf52840"
SERIAL_PORT = os.environ.get("SERIAL_PORT", "/dev/tty.usbmodem0010502058091")
DEVICE_CN = "nrf52840dk_nrf52840"

PI_USER = os.environ.get("PI_USER", "vini")
PI_HOST = os.environ.get("PI_HOST", "10.12.194.1")
PI_PASSWORD = os.environ.get("PI_PASSWORD", "rasppi")
PI_WORKDIR = os.environ.get("PI_WORKDIR", f"/home/{PI_USER}/pqc_ble_mqtt")
PI_ADAPTER = os.environ.get("PI_ADAPTER", "hci0")
PI_MOSQUITTO = os.environ.get("PI_MOSQUITTO", "/usr/sbin/mosquitto")

BLE_DEVICE_NAME = os.environ.get("BLE_DEVICE_NAME", "PQC52840")
BLE_DEVICE_ADDR = os.environ.get("BLE_DEVICE_ADDR", "")
BLE_DEVICE_ADDR_TYPE = os.environ.get("BLE_DEVICE_ADDR_TYPE", "random")
L2CAP_PSM = os.environ.get("L2CAP_PSM", "0x0080")
BRIDGE_MTU = int(os.environ.get("BRIDGE_MTU", "672"))
DISABLE_WIFI_DURING_BLE = os.environ.get("PI_DISABLE_WIFI_DURING_BLE", "1").lower() not in {
    "0",
    "false",
    "no",
}

RUNS_PER_CASE = int(os.environ.get("RUNS_PER_CASE", "1"))
HANDSHAKE_TIMEOUT_S = int(os.environ.get("HANDSHAKE_TIMEOUT", "300"))
BOOT_DRAIN_S = float(os.environ.get("BOOT_DRAIN_SECONDS", "2"))
SHUTDOWN_DRAIN_S = float(os.environ.get("SHUTDOWN_DRAIN_SECONDS", "8"))
RADIO_COOLDOWN_S = float(os.environ.get("RADIO_COOLDOWN_SECONDS", "6"))

RESULTS_CSV = Path(os.environ.get("RESULTS_CSV", PROJECT_DIR / "pqc_benchmark_results.csv"))
RUNS_CSV = Path(os.environ.get("RUNS_CSV", PROJECT_DIR / "pqc_benchmark_runs.csv"))

DOCKER_IMAGE = os.environ.get("PQC_DOCKER_IMAGE", "pqc-openssl:3.5")
DOCKERFILE_DIR = PROJECT_DIR / "docker" / "pqc-openssl"
CERT_CONTAINER_NAME = "pqc_auto_gen"

NORDIC_PYTHON = "/opt/nordic/ncs/toolchains/0c0f19d91c/opt/python@3.12/bin/python3.12"
ZEPHYR_BASE = "/opt/nordic/ncs/v3.3.0/zephyr"
TOOLCHAIN_ROOT = "/opt/nordic/ncs/toolchains/0c0f19d91c"


# ---------------------------------------------------------------------------
# Benchmark case definitions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class KemInfo:
    name: str
    wolfssl_macro: str
    openssl_group: str
    nist_level: int
    public_key_bytes: int
    ciphertext_bytes: int
    shared_secret_bytes: int
    family : str


@dataclass(frozen=True)
class SigInfo:
    name: str
    issuer_key_type: str
    leaf_key_type: str
    nist_level: int
    public_key_bytes: int
    private_key_bytes: int
    signature_bytes: int
    family : str


@dataclass(frozen=True)
class BenchmarkCase:
    kem: KemInfo
    sig: SigInfo

    @property
    def case_id(self) -> str:
        return f"{self.kem.name}_{self.sig.name}"


KEMS = [
    KemInfo("MLKEM512", "WOLFSSL_ML_KEM_512", "MLKEM512", 1, 800, 768, 32, "pqc"),
    KemInfo("MLKEM768", "WOLFSSL_ML_KEM_768", "MLKEM768", 3, 1184, 1088, 32, "pqc"),
    KemInfo("MLKEM1024", "WOLFSSL_ML_KEM_1024", "MLKEM1024", 5, 1568, 1568, 32, "pqc"),
    KemInfo("SecP256r1MLKEM768", "WOLFSSL_SEC_P256R1_ML_KEM_768", "SecP256r1MLKEM768", 3, 65 + 1184, 65 + 1088, 32 + 32, "pqc"),
    KemInfo("X25519MLKEM768", "WOLFSSL_X25519_ML_KEM_768", "X25519MLKEM768", 3, 32 + 1184, 32 + 1088, 32 + 32, "pqc"),
    KemInfo("SecP384r1MLKEM1024", "WOLFSSL_SEC_P384R1_ML_KEM_1024", "SecP384r1MLKEM1024", 5, 97 + 1568, 97 + 1568, 48 + 32, "pqc"),
    KemInfo("ECDHE-P-256", "WOLFSSL_ECDHE_P_256", "ECDHE-P-256", 1, 65, 65, 32, "classic"),
    KemInfo("ECDHE-P-384", "WOLFSSL_ECDHE_P_384", "ECDHE-P-384", 3, 97, 97, 48, "classic"),
    KemInfo("ECDHE-P-521", "WOLFSSL_ECDHE_P_521", "ECDHE-P-521", 5, 133, 133, 66, "classic"),
]

SIGS = [
    # ECDSA
    # SigInfo("ECDSA-P-256", "ec:prime256v1", "ec:prime256v1", 1, 64, 32, 64, "classic"),
    # SigInfo("ECDSA-P-384", "ec:secp384r1", "ec:secp384r1", 3, 96, 48, 96, "classic"),
    # SigInfo("ECDSA-P-521", "ec:secp521r1", "ec:secp521r1", 5, 132, 66, 132, "classic"),

    # SigInfo("ML-DSA-44", "ML-DSA-44", "ML-DSA-44", 2, 1312, 2560, 2420, "pqc"),
    # SigInfo("ML-DSA-65", "ML-DSA-65", "ML-DSA-65", 3, 1952, 4032, 3309, "pqc"),
    # SigInfo("ML-DSA-87", "ML-DSA-87", "ML-DSA-87", 5, 2592, 4896, 4627, "pqc"),
    # SLH-DSA signs the certificate chain. TLS CertificateVerify remains ECDSA
    # because standardized TLS SLH-DSA schemes are not available in this stack.
    # SigInfo("SLH-DSA-SHAKE-128s", "SLH-DSA-SHAKE-128s", "ec:prime256v1", 1, 32, 64, 7856, "pqc"),
    # SigInfo("SLH-DSA-SHAKE-192s", "SLH-DSA-SHAKE-192s", "ec:secp384r1", 3, 48, 96, 16224, "pqc"),
    # SigInfo("SLH-DSA-SHAKE-256s", "SLH-DSA-SHAKE-256s", "ec:secp521r1", 5, 64, 128, 29792, "pqc"),
    # RSA
    SigInfo("RSA-PSS-3072", "RSA-PSS-3072", "RSA-PSS-3072", 1, 384, 384, 384, "classic"),
    SigInfo("RSA-PSS-7680", "RSA-PSS-7680", "RSA-PSS-7680", 3, 960, 960, 960, "classic"),
    SigInfo("RSA-PSS-15360", "RSA-PSS-15360", "RSA-PSS-15360", 5, 1920, 1920, 1920, "classic"),
]


# ---------------------------------------------------------------------------
# CSV schemas
# ---------------------------------------------------------------------------


RESULT_FIELDS = [
    "case_id",
    "kex_group",
    "kex_nist_level",
    "kex_public_key_bytes",
    "kex_ciphertext_bytes",
    "kex_shared_secret_bytes",
    "cert_sig_alg",
    "sig_nist_level",
    "sig_public_key_bytes",
    "sig_private_key_bytes",
    "sig_signature_bytes",
    "status",
    "success_count",
    "fail_count",
    "timeout_count",
    "mean_handshake_ms",
    "median_handshake_ms",
    "p95_handshake_ms",
    "min_handshake_ms",
    "max_handshake_ms",
    "stddev_handshake_ms",
    "handshake_throughput_hps",
    "mean_raw_handshake_ms",
    "median_raw_handshake_ms",
    "p95_raw_handshake_ms",
    "min_raw_handshake_ms",
    "max_raw_handshake_ms",
    "stddev_raw_handshake_ms",
    "raw_handshake_throughput_hps",
    "mean_full_connect_ms",
    "connections_per_second",
    "mean_client_cpu_ms",
    "mean_client_cpu_pct",
    "mean_client_thread_analyzer_cpu_pct",
    "max_client_thread_cpu_pct",
    "max_client_thread_stack_used_bytes",
    "max_client_thread_stack_pct",
    "max_client_wolfssl_peak_bytes",
    "max_client_wolfssl_failures",
    "max_client_heap_current_bytes",
    "max_client_heap_peak_bytes",
    "client_ram_total_bytes",
    "client_rom_total_bytes",
]

RUN_FIELDS = [
    "timestamp",
    "case_id",
    "run_index",
    "status",
    "handshake_ms",
    "raw_handshake_ms",
    "full_connect_ms",
    "failure_reason",
    "client_wolfssl_peak_bytes",
    "client_wolfssl_failures",
    "client_heap_current_bytes",
    "client_heap_peak_bytes",
    "client_cpu_cycles",
    "client_cycle_hz",
    "client_thread_analyzer_cpu_pct",
    "client_thread_max_cpu_pct",
    "client_thread_max_stack_used_bytes",
    "client_thread_max_stack_pct",
    "client_ram_total_bytes",
    "client_rom_total_bytes",
]


@dataclass
class RunResult:
    case_id: str
    run_index: int
    status: str = "TIMEOUT"
    handshake_ms: float | None = None
    raw_handshake_ms: float | None = None
    full_connect_ms: float | None = None
    failure_reason: str = ""
    wolfssl_peak_bytes: int = 0
    wolfssl_failures: int = 0
    heap_current_bytes: int = 0
    heap_peak_bytes: int = 0
    client_cpu_cycles: int = 0
    client_cycle_hz: int = 0
    thread_analyzer_active: bool = False
    thread_analyzer_cpu_pct: int | None = None
    thread_analyzer_cpu_pct_accum: int = 0
    thread_max_cpu_pct: int = 0
    thread_max_stack_used_bytes: int = 0
    thread_max_stack_pct: int = 0
    ram_total_bytes: int = 0
    rom_total_bytes: int = 0
    serial_lines: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------


def die(message: str) -> None:
    print(f"[ERROR] {message}")
    raise SystemExit(1)


def now_utc_for_pi() -> str:
    return dt.datetime.now(dt.UTC).strftime("%Y-%m-%d %H:%M:%S")


def print_step(message: str) -> None:
    print(f"\n--- {message} ---")


def run_cmd(cmd: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None,
            ignore_errors: bool = False) -> subprocess.CompletedProcess:
    print(f"\n[RUNNING] {' '.join(shlex.quote(part) for part in cmd)}")
    result = subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env)
    if result.returncode != 0 and not ignore_errors:
        die(f"Command failed with return code {result.returncode}")
    return result


def run_password_cmd(cmd: list[str], *, ignore_errors: bool = False,
                     popen: bool = False) -> subprocess.CompletedProcess | subprocess.Popen:
    """Run ssh/scp through expect when PI_PASSWORD is configured."""
    if not PI_PASSWORD:
        if popen:
            return subprocess.Popen(cmd)
        result = subprocess.run(cmd)
        if result.returncode != 0 and not ignore_errors:
            die(f"Command failed with return code {result.returncode}")
        return result

    def tcl_word(value: str) -> str:
        return "{" + value.replace("\\", "\\\\").replace("{", "\\{").replace("}", "\\}") + "}"

    tcl_cmd = " ".join(tcl_word(part) for part in cmd)
    expect_script = "set cmd [list " + tcl_cmd + r''']
set timeout -1
log_user 1
spawn {*}$cmd
expect {
    -re "(?i)are you sure.*yes/no.*" {
        send "yes\r"
        exp_continue
    }
    -re "(?i)password:" {
        send "$env(PI_PASSWORD)\r"
        exp_continue
    }
    eof
}
catch wait result
exit [lindex $result 3]
'''
    env = os.environ.copy()
    env["PI_PASSWORD"] = PI_PASSWORD
    wrapped = ["expect", "-c", expect_script]

    if popen:
        return subprocess.Popen(wrapped, env=env)

    result = subprocess.run(wrapped, env=env)
    if result.returncode != 0 and not ignore_errors:
        die(f"Command failed with return code {result.returncode}")
    return result


def pi_ssh_cmd(remote_cmd: str) -> list[str]:
    return [
        "ssh",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=4",
        f"{PI_USER}@{PI_HOST}",
        remote_cmd,
    ]


def run_pi_cmd(remote_cmd: str, *, ignore_errors: bool = False) -> subprocess.CompletedProcess:
    print(f"\n[PI RUNNING] ssh {PI_USER}@{PI_HOST} {remote_cmd}")
    return run_password_cmd(pi_ssh_cmd(remote_cmd), ignore_errors=ignore_errors)  # type: ignore[return-value]


def popen_pi_cmd(remote_cmd: str) -> subprocess.Popen:
    print(f"\n[PI LAUNCHING] ssh {PI_USER}@{PI_HOST} {remote_cmd}")
    return run_password_cmd(pi_ssh_cmd(remote_cmd), popen=True)  # type: ignore[return-value]


def scp_to_pi(local_path: Path, remote_path: str) -> None:
    print(f"\n[PI COPYING] {local_path} -> {PI_USER}@{PI_HOST}:{remote_path}")
    run_password_cmd([
        "scp",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-r",
        str(local_path),
        f"{PI_USER}@{PI_HOST}:{remote_path}",
    ])


def backup_if_legacy_csv(path: Path, expected_fields: list[str]) -> None:
    if not path.exists() or path.stat().st_size == 0:
        return
    with path.open(newline="") as f:
        reader = csv.reader(f)
        header = next(reader, [])
    if header == expected_fields:
        return
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = path.with_suffix(f".legacy-{stamp}.csv")
    shutil.move(path, backup)
    print(f"[CSV] Existing {path.name} used an old schema; backed it up to {backup.name}.")


def append_csv_row(path: Path, fields: list[str], row: dict[str, object]) -> None:
    backup_if_legacy_csv(path, fields)
    file_exists = path.exists() and path.stat().st_size > 0
    with path.open("a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        if not file_exists:
            writer.writeheader()
        writer.writerow({field: row.get(field, "") for field in fields})


def percentile_95(values: list[float]) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    index = 0.95 * (len(ordered) - 1)
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = index - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def mean(values: list[float]) -> float | None:
    return statistics.mean(values) if values else None


def median(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def stddev(values: list[float]) -> float | None:
    return statistics.stdev(values) if len(values) > 1 else (0.0 if values else None)


def fmt(value: float | int | None) -> str:
    if value is None:
        return ""
    if isinstance(value, int):
        return str(value)
    return f"{value:.3f}"


# ---------------------------------------------------------------------------
# Docker/OpenSSL certificate generation
# ---------------------------------------------------------------------------


def ensure_docker_running() -> None:
    print_step("STEP 0: CHECKING DOCKER STATUS")
    result = subprocess.run(["docker", "info"], capture_output=True)
    if result.returncode == 0:
        print("[OK] Docker is already running.")
        return

    if sys.platform == "darwin":
        print("[INFO] Docker is not running. Starting Docker Desktop...")
        subprocess.run(["open", "-a", "Docker"])
    else:
        die("Docker is not running. Start Docker and rerun the benchmark.")

    deadline = time.time() + 90
    while time.time() < deadline:
        if subprocess.run(["docker", "info"], capture_output=True).returncode == 0:
            print("[OK] Docker daemon is up.")
            return
        time.sleep(2)
    die("Timed out waiting for Docker.")


def ensure_pqc_image() -> None:
    result = subprocess.run(["docker", "image", "inspect", DOCKER_IMAGE], capture_output=True)
    if result.returncode != 0:
        run_cmd(["docker", "build", "-t", DOCKER_IMAGE, str(DOCKERFILE_DIR)])

    checks = (
        "openssl version && "
        "openssl list -signature-algorithms | grep -q SLH-DSA-SHAKE-256s && "
        "openssl list -kem-algorithms | grep -Eq 'MLKEM512|ML-KEM-512'"
    )
    run_cmd(["docker", "run", "--rm", DOCKER_IMAGE, "sh", "-c", checks])


def rsa_pss_bits(key_type: str) -> int | None:
    match = re.fullmatch(r"RSA-PSS-(\d+)", key_type)
    return int(match.group(1)) if match else None


def rsa_pss_hash_args(bits: int) -> list[str]:
    if bits <= 3072:
        return ["-sha256"]
    if bits <= 7680:
        return ["-sha384"]
    return ["-sha512"]


def rsa_pss_sigopt_args(bits: int) -> list[str]:
    return [
        *rsa_pss_hash_args(bits),
        "-sigopt", "rsa_padding_mode:pss",
        "-sigopt", "rsa_pss_saltlen:-1",
    ]


def rsa_fp_max_bits(bits: int) -> int:
    """wolfSSL fastmath needs FP_MAX_BITS >= 2 * RSA modulus bits."""
    if bits <= 4096:
        return 8192
    if bits <= 8192:
        return 16384
    return 32768


def make_key_args(key_type: str) -> list[str]:
    rsa_bits = rsa_pss_bits(key_type)
    if rsa_bits is not None:
        return ["-newkey", f"rsa:{rsa_bits}"]
    if not key_type.startswith("ec:"):
        return ["-newkey", key_type]
    curve_name = key_type.split(":", 1)[1]
    return ["-newkey", "ec", "-pkeyopt", f"ec_paramgen_curve:{curve_name}"]


def make_sign_args(key_type: str) -> list[str]:
    rsa_bits = rsa_pss_bits(key_type)
    if rsa_bits is not None:
        # Keep X.509 certificate signatures as normal RSA/PKCS#1 v1.5.
        #
        # wolfSSL on the nRF52840 rejects rsassaPss-signed certificates in this
        # configuration with ASN_SIG_CONFIRM_E (-155). TLS 1.3 still negotiates
        # RSA-PSS for CertificateVerify because the leaf key is RSA; this only
        # changes the CA/leaf certificate-chain signature encoding.
        return rsa_pss_hash_args(rsa_bits)
    return []


def generate_certificates(case: BenchmarkCase) -> None:
    print_step(f"STEP 1: GENERATING {case.case_id} CERTIFICATES")
    CERT_DIR.mkdir(exist_ok=True)
    for path in CERT_DIR.iterdir():
        if path.suffix in {".crt", ".key", ".csr", ".der", ".srl"}:
            path.unlink()

    issuer_key_args = make_key_args(case.sig.issuer_key_type)
    leaf_key_args = make_key_args(case.sig.leaf_key_type)
    issuer_sign_args = make_sign_args(case.sig.issuer_key_type)
    leaf_sign_args = make_sign_args(case.sig.leaf_key_type)

    if case.sig.issuer_key_type != case.sig.leaf_key_type:
        print("[INFO] SLH-DSA signs the certificate chain; TLS leaf keys remain ECDSA.")
    if rsa_pss_bits(case.sig.issuer_key_type) is not None:
        print(
            f"[INFO] {case.sig.name} uses RSA keys. X.509 certificates are "
            "PKCS#1-signed for wolfSSL compatibility; TLS 1.3 CertificateVerify "
            "still uses RSA-PSS."
        )

    run_cmd(["docker", "rm", "-f", CERT_CONTAINER_NAME], ignore_errors=True)
    run_cmd(["docker", "run", "-d", "--name", CERT_CONTAINER_NAME, DOCKER_IMAGE, "tail", "-f", "/dev/null"])

    try:
        docker_openssl(["req", "-x509", "-new", *issuer_key_args,
                        "-keyout", "/tmp/ca.key", "-out", "/tmp/ca.crt",
                        "-nodes", "-subj", "/CN=PQC_Root", "-days", "365",
                        *issuer_sign_args])
        docker_openssl(["req", "-new", *leaf_key_args,
                        "-keyout", "/tmp/client.key", "-out", "/tmp/client.csr",
                        "-nodes", "-subj", f"/CN={DEVICE_CN}",
                        *leaf_sign_args])
        docker_openssl(["x509", "-req", "-in", "/tmp/client.csr",
                        "-CA", "/tmp/ca.crt", "-CAkey", "/tmp/ca.key",
                        "-CAcreateserial", "-out", "/tmp/client.crt", "-days", "365",
                        *issuer_sign_args])
        docker_openssl(["x509", "-in", "/tmp/client.crt", "-outform", "DER",
                        "-out", "/tmp/client_cert.der"])
        docker_openssl(["pkey", "-in", "/tmp/client.key", "-outform", "DER",
                        "-out", "/tmp/client_key.der"])
        docker_openssl(["x509", "-in", "/tmp/ca.crt", "-outform", "DER",
                        "-out", "/tmp/ca_cert.der"])

        docker_openssl(["req", "-new", *leaf_key_args,
                        "-keyout", "/tmp/server.key", "-out", "/tmp/server.csr",
                        "-nodes", "-subj", "/CN=localhost",
                        *leaf_sign_args])
        docker_openssl(["x509", "-req", "-in", "/tmp/server.csr",
                        "-CA", "/tmp/ca.crt", "-CAkey", "/tmp/ca.key",
                        "-CAcreateserial", "-out", "/tmp/server.crt", "-days", "365",
                        *issuer_sign_args])

        for name in [
            "ca.crt",
            "client.crt",
            "client.key",
            "server.crt",
            "server.key",
            "ca_cert.der",
            "client_cert.der",
            "client_key.der",
        ]:
            run_cmd(["docker", "cp", f"{CERT_CONTAINER_NAME}:/tmp/{name}", str(CERT_DIR / name)])
    finally:
        run_cmd(["docker", "rm", "-f", CERT_CONTAINER_NAME], ignore_errors=True)


def docker_openssl(args: list[str]) -> None:
    run_cmd(["docker", "exec", CERT_CONTAINER_NAME, "openssl", *args])


def write_c_header(der_path: Path, header_path: Path, var_name: str, guard: str) -> None:
    data = der_path.read_bytes()
    print(f"[FORMATTING] {der_path.name} -> {header_path}")
    with header_path.open("w") as f:
        f.write(f"#ifndef {guard}\n#define {guard}\n\n")
        f.write(f"const unsigned char {var_name}[] = {{\n")
        hex_bytes = [f"0x{byte:02x}" for byte in data]
        for offset in range(0, len(hex_bytes), 12):
            chunk = ", ".join(hex_bytes[offset:offset + 12])
            comma = "," if offset + 12 < len(hex_bytes) else ""
            f.write(f"    {chunk}{comma}\n")
        f.write("};\n\n")
        f.write(f"const unsigned int {var_name}_len = {len(data)};\n\n")
        f.write("#endif\n")


def update_nrf_certificate_headers() -> None:
    write_c_header(CERT_DIR / "client_cert.der", SRC_DIR / "client_cert.h", "client_der", "CLIENT_CERT_H")
    write_c_header(CERT_DIR / "client_key.der", SRC_DIR / "client_key.h", "client_key_der", "CLIENT_KEY_H")
    write_c_header(CERT_DIR / "ca_cert.der", SRC_DIR / "ca_cert.h", "ca_der", "CA_CERT_H")


def write_openssl_conf(case: BenchmarkCase) -> None:
    (CERT_DIR / "openssl.cnf").write_text(f"""openssl_conf = openssl_init

[openssl_init]
ssl_conf = ssl_sect

[ssl_sect]
system_default = system_default_sect

[system_default_sect]
MinProtocol = TLSv1.3
Groups = {case.kem.openssl_group}
""")


def write_mosquitto_conf() -> None:
    (CERT_DIR / "mosquitto.conf").write_text(f"""listener 8883
allow_anonymous false
password_file {PI_WORKDIR}/certs/passwd
cafile {PI_WORKDIR}/certs/ca.crt
certfile {PI_WORKDIR}/certs/server.crt
keyfile {PI_WORKDIR}/certs/server.key
require_certificate true
use_identity_as_username true
""")
    passwd = CERT_DIR / "passwd"
    if not passwd.exists():
        die(f"{passwd} is missing. Keep the existing Mosquitto password file in generated_certs/passwd.")


# ---------------------------------------------------------------------------
# Raspberry Pi setup and runtime
# ---------------------------------------------------------------------------


def ensure_raspberry_pi_ready() -> None:
    print_step("STEP 2: PREPARING RASPBERRY PI")
    q_workdir = shlex.quote(PI_WORKDIR)
    run_pi_cmd(f"mkdir -p {q_workdir}/certs {q_workdir}/logs")
    scp_to_pi(PI_DIR / "ble_mqtt_bridge.c", f"{PI_WORKDIR}/ble_mqtt_bridge.c")

    setup_cmd = f"""
set -e
cd {q_workdir}
need_sudo=0
for cmd in gcc pkg-config openssl mosquitto_pub; do
    command -v "$cmd" >/dev/null 2>&1 || need_sudo=1
done
[ -x {shlex.quote(PI_MOSQUITTO)} ] || need_sudo=1
pkg-config --exists bluez || need_sudo=1
if [ "$need_sudo" = 1 ]; then
    sudo apt-get update
    sudo apt-get install -y bluez libbluetooth-dev mosquitto mosquitto-clients openssl build-essential pkg-config
fi
openssl version
openssl list -kem-algorithms | grep -Eq 'MLKEM512|ML-KEM-512|ML-KEM512'
openssl list -signature-algorithms | grep -q 'SLH-DSA-SHAKE-256s'
gcc -O2 -Wall -Wextra -o ble_mqtt_bridge ble_mqtt_bridge.c $(pkg-config --cflags --libs bluez)
sudo date -u -s {shlex.quote(now_utc_for_pi())} >/dev/null
sudo sed -i -E 's/^#?MinConnectionInterval=.*/MinConnectionInterval=12/; s/^#?MaxConnectionInterval=.*/MaxConnectionInterval=12/; s/^#?ConnectionLatency=.*/ConnectionLatency=0/; s/^#?ConnectionSupervisionTimeout=.*/ConnectionSupervisionTimeout=400/' /etc/bluetooth/main.conf
sudo systemctl restart bluetooth
"""
    run_pi_cmd(setup_cmd)


def deploy_pi_assets() -> None:
    print_step("STEP 3: DEPLOYING CERTS TO RASPBERRY PI")
    for name in [
        "ca.crt",
        "client.crt",
        "client.key",
        "server.crt",
        "server.key",
        "openssl.cnf",
        "passwd",
        "mosquitto.conf",
    ]:
        scp_to_pi(CERT_DIR / name, f"{PI_WORKDIR}/certs/{name}")

    q_workdir = shlex.quote(PI_WORKDIR)
    run_pi_cmd(f"chmod 600 {q_workdir}/certs/*.key && ls -l {q_workdir}/certs")


def stop_pi_services() -> None:
    q_workdir = shlex.quote(PI_WORKDIR)
    mosquitto_conf_pattern = f"[/]{PI_WORKDIR.lstrip('/')}/certs/mosquitto.conf"
    wifi_restore = (
        "sudo nmcli radio wifi on 2>/dev/null || sudo ip link set wlan0 up 2>/dev/null || true"
        if DISABLE_WIFI_DURING_BLE else
        "true"
    )
    run_pi_cmd(
        f"if [ -f {q_workdir}/mosquitto.pid ]; then "
        f"sudo kill $(cat {q_workdir}/mosquitto.pid) || true; "
        f"rm -f {q_workdir}/mosquitto.pid; fi; "
        f"pkill -f '{PI_WORKDIR}/ble_mqtt_bridg[e]' 2>/dev/null || true; "
        f"pids=$(pgrep -f {shlex.quote(mosquitto_conf_pattern)} || true); "
        "if [ -n \"$pids\" ]; then sudo kill $pids || true; fi; "
        f"{wifi_restore}",
        ignore_errors=True,
    )


def start_pi_mosquitto() -> None:
    print_step("STEP 3B: STARTING PI MOSQUITTO")
    stop_pi_services()
    q_workdir = shlex.quote(PI_WORKDIR)
    run_pi_cmd(
        f"cd {q_workdir} && "
        f"setsid -f env OPENSSL_CONF={q_workdir}/certs/openssl.cnf "
        f"{shlex.quote(PI_MOSQUITTO)} -c {q_workdir}/certs/mosquitto.conf -v "
        f"> {q_workdir}/logs/mosquitto.log 2>&1 < /dev/null; "
        f"sleep 1; "
        f"pgrep -n -f 'mosquitto -c {PI_WORKDIR}/certs/mosquitto.conf' > {q_workdir}/mosquitto.pid || true; "
        f"tail -30 {q_workdir}/logs/mosquitto.log"
    )


def start_pi_bridge() -> subprocess.Popen:
    args = [
        f"--adapter {shlex.quote(PI_ADAPTER)}",
        f"--name {shlex.quote(BLE_DEVICE_NAME)}",
        f"--psm {shlex.quote(L2CAP_PSM)}",
        "--tcp-host 127.0.0.1",
        "--tcp-port 8883",
        f"--mtu {BRIDGE_MTU}",
        "--scan-timeout 2",
        "--forget-cache",
        "--no-acl-prime",
    ]
    if DISABLE_WIFI_DURING_BLE:
        args.append("--disable-wifi")
    if BLE_DEVICE_ADDR:
        args.append(f"--addr {shlex.quote(BLE_DEVICE_ADDR)}")
        args.append(f"--addr-type {shlex.quote(BLE_DEVICE_ADDR_TYPE)}")

    q_workdir = shlex.quote(PI_WORKDIR)
    return popen_pi_cmd(f"cd {q_workdir} && sudo {q_workdir}/ble_mqtt_bridge {' '.join(args)}")


# ---------------------------------------------------------------------------
# nRF build/flash and serial capture
# ---------------------------------------------------------------------------


def west_env() -> dict[str, str]:
    env = os.environ.copy()
    env["ZEPHYR_BASE"] = ZEPHYR_BASE
    env.setdefault("ZEPHYR_TOOLCHAIN_VARIANT", "zephyr")
    env.setdefault("ZEPHYR_SDK_INSTALL_DIR", f"{TOOLCHAIN_ROOT}/opt/zephyr-sdk")
    env["PATH"] = os.pathsep.join([
        f"{TOOLCHAIN_ROOT}/nrfutil/bin",
        f"{TOOLCHAIN_ROOT}/bin",
        env.get("PATH", ""),
    ])
    return env


def build_and_flash(case: BenchmarkCase) -> None:
    print_step("STEP 4: WEST BUILD & FLASH")
    if BUILD_DIR.exists():
        print("[CLEANING] Removing old build directory...")
        shutil.rmtree(BUILD_DIR)

    extra_cflags = f"-DTARGET_PQC_GROUP={case.kem.wolfssl_macro}"
    rsa_bits = rsa_pss_bits(case.sig.leaf_key_type) or rsa_pss_bits(case.sig.issuer_key_type)
    if rsa_bits is not None:
        fp_max = rsa_fp_max_bits(rsa_bits)
        extra_cflags += f" -DFP_MAX_BITS={fp_max}"
        print(f"[INFO] Building RSA-{rsa_bits} case with FP_MAX_BITS={fp_max}.")
    build_cmd = [
        NORDIC_PYTHON,
        "-m",
        "west",
        "-z",
        ZEPHYR_BASE,
        "build",
        "-p",
        "always",
        "-b",
        BOARD,
        "--sysbuild",
        "--",
        f"-DEXTRA_CFLAGS={extra_cflags}",
    ]
    run_cmd(build_cmd, cwd=PROJECT_DIR, env=west_env())

    print(f"\n[FLASHING] Uploading to {BOARD}...")
    run_cmd([NORDIC_PYTHON, "-m", "west", "-z", ZEPHYR_BASE, "flash"],
            cwd=PROJECT_DIR, env=west_env())


def open_serial_port() -> serial.Serial:
    print(f"\n[WAITING] Allowing {BOARD} to boot and USB to enumerate...")
    time.sleep(5)
    for attempt in range(1, 8):
        try:
            return serial.Serial(SERIAL_PORT, 115200, timeout=0.5)
        except serial.SerialException as exc:
            print(f"[-] Serial port not ready ({attempt}/7): {exc}")
            time.sleep(2)
    die(f"Could not open serial port {SERIAL_PORT}")


HEAP_RE = re.compile(r"\[WOLFSSL HEAP\].*used=(\d+)\s+peak=(\d+)\s+free=(\d+)/(\d+)")
CPU_RE = re.compile(r"Client_CPU_Cycles:\s*(\d+)\s+Cycle_Hz:\s*(\d+)")
THREAD_ANALYZER_RE = re.compile(
    r"^\s*(?P<name>[^:]+?)\s*:\s*STACK:\s*unused\s+(?P<unused>\d+)\s+"
    r"usage\s+(?P<used>\d+)\s*/\s*(?P<total>\d+)\s+\((?P<stack_pct>\d+)\s+%\);"
    r"\s*CPU:\s*(?P<cpu_pct>\d+)\s+%"
)
THREAD_ANALYZER_STACK_ONLY_RE = re.compile(
    r"^\s*(?P<name>[^:]+?)\s*:\s*STACK:\s*unused\s+(?P<unused>\d+)\s+"
    r"usage\s+(?P<used>\d+)\s*/\s*(?P<total>\d+)\s+\((?P<stack_pct>\d+)\s+%\)"
)
RAM_TOTAL_RE = re.compile(r"Client_RAM_Total_Bytes:\s*(\d+)")
ROM_TOTAL_RE = re.compile(r"Client_ROM_Total_Bytes:\s*(\d+)")


def update_run_metrics_from_line(result: RunResult, line: str) -> None:
    if "[WOLFSSL HEAP] allocation failed" in line or "[WOLFSSL HEAP] realloc failed" in line:
        result.wolfssl_failures += 1

    cpu_match = CPU_RE.search(line)
    if cpu_match:
        result.client_cpu_cycles = int(cpu_match.group(1))
        result.client_cycle_hz = int(cpu_match.group(2))

    ram_match = RAM_TOTAL_RE.search(line)
    if ram_match:
        result.ram_total_bytes = int(ram_match.group(1))

    rom_match = ROM_TOTAL_RE.search(line)
    if rom_match:
        result.rom_total_bytes = int(rom_match.group(1))

    if "Thread_Analyzer_Begin" in line:
        result.thread_analyzer_active = True
        result.thread_analyzer_cpu_pct_accum = 0
        result.thread_analyzer_cpu_pct = None
        result.thread_max_cpu_pct = 0
        result.thread_max_stack_used_bytes = 0
        result.thread_max_stack_pct = 0
        return

    if "Thread_Analyzer_End" in line:
        result.thread_analyzer_active = False
        result.thread_analyzer_cpu_pct = min(result.thread_analyzer_cpu_pct_accum, 100)
        return

    thread_match = THREAD_ANALYZER_RE.search(line)
    if result.thread_analyzer_active and thread_match:
        thread_name = thread_match.group("name").strip()
        used = int(thread_match.group("used"))
        stack_pct = int(thread_match.group("stack_pct"))
        cpu_pct = int(thread_match.group("cpu_pct"))

        if thread_name != "idle":
            result.thread_analyzer_cpu_pct_accum += cpu_pct
        result.thread_max_cpu_pct = max(result.thread_max_cpu_pct, cpu_pct)
        result.thread_max_stack_used_bytes = max(result.thread_max_stack_used_bytes, used)
        result.thread_max_stack_pct = max(result.thread_max_stack_pct, stack_pct)

    stack_only_match = THREAD_ANALYZER_STACK_ONLY_RE.search(line)
    if result.thread_analyzer_active and stack_only_match:
        used = int(stack_only_match.group("used"))
        stack_pct = int(stack_only_match.group("stack_pct"))

        result.thread_max_stack_used_bytes = max(result.thread_max_stack_used_bytes, used)
        result.thread_max_stack_pct = max(result.thread_max_stack_pct, stack_pct)

    match = HEAP_RE.search(line)
    if not match:
        return

    used = int(match.group(1))
    peak = int(match.group(2))
    result.heap_current_bytes = max(result.heap_current_bytes, used)
    result.heap_peak_bytes = max(result.heap_peak_bytes, peak)
    result.wolfssl_peak_bytes = max(result.wolfssl_peak_bytes, peak)


def drain_serial_output(ser: serial.Serial, seconds: float, reason: str,
                        result: RunResult | None = None) -> None:
    print(f"\n[LOG] Draining {reason} for {seconds:g}s...")
    deadline = time.time() + seconds
    old_timeout = ser.timeout
    ser.timeout = 0.2
    try:
        while time.time() < deadline:
            raw = ser.readline()
            if not raw:
                continue
            line = raw.decode("utf-8", errors="ignore").strip()
            if not line:
                continue
            print(f"[{BOARD}] {line}")
            if result:
                result.serial_lines.append(line)
                update_run_metrics_from_line(result, line)
            if "Session ended. Re-arming for next connection" in line:
                break
    except serial.SerialException:
        print("[-] Board disconnected while draining serial output.")
    finally:
        ser.timeout = old_timeout


def run_single_handshake(case: BenchmarkCase, ser: serial.Serial, run_index: int) -> RunResult:
    result = RunResult(case.case_id, run_index)
    drain_serial_output(ser, BOOT_DRAIN_S, "queued board output", result)

    print(f"\n[RUN {run_index}/{RUNS_PER_CASE}] Starting Mosquitto and BLE bridge...")
    start_pi_mosquitto()
    bridge_start = time.perf_counter()
    bridge_proc = start_pi_bridge()

    print("[LISTENING] Waiting for Zephyr handshake result...")
    deadline = time.time() + HANDSHAKE_TIMEOUT_S

    try:
        while time.time() < deadline:
            try:
                raw = ser.readline()
            except serial.SerialException:
                result.status = "FAIL"
                result.failure_reason = "serial disconnected"
                break

            if not raw:
                continue
            line = raw.decode("utf-8", errors="ignore").strip()
            if not line:
                continue

            print(f"[{BOARD}] {line}")
            result.serial_lines.append(line)
            update_run_metrics_from_line(result, line)

            if "Handshake_Time_MS:" in line:
                value = float(line.split(":", 1)[1].strip())
                result.status = "SUCCESS"
                result.handshake_ms = value
                result.raw_handshake_ms = value
                result.full_connect_ms = (time.perf_counter() - bridge_start) * 1000.0
                break

            if "TLS Handshake Failed:" in line:
                result.status = "FAIL"
                result.failure_reason = line.split(":", 1)[1].strip()
                result.full_connect_ms = (time.perf_counter() - bridge_start) * 1000.0
                break
        else:
            result.status = "TIMEOUT"
            result.failure_reason = "handshake timeout"
            result.full_connect_ms = (time.perf_counter() - bridge_start) * 1000.0

        if result.status == "SUCCESS":
            print("[INFO] Board will close TLS itself after the benchmark result.")
            drain_serial_output(ser, SHUTDOWN_DRAIN_S, "board shutdown output", result)
        else:
            drain_serial_output(ser, 3, "failure output", result)
    finally:
        bridge_proc.terminate()
        try:
            bridge_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            bridge_proc.kill()
        stop_pi_services()

    append_run_csv(result)
    return result


# ---------------------------------------------------------------------------
# CSV aggregation
# ---------------------------------------------------------------------------


def append_run_csv(result: RunResult) -> None:
    append_csv_row(RUNS_CSV, RUN_FIELDS, {
        "timestamp": dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "case_id": result.case_id,
        "run_index": result.run_index,
        "status": result.status,
        "handshake_ms": fmt(result.handshake_ms),
        "raw_handshake_ms": fmt(result.raw_handshake_ms),
        "full_connect_ms": fmt(result.full_connect_ms),
        "failure_reason": result.failure_reason,
        "client_wolfssl_peak_bytes": result.wolfssl_peak_bytes,
        "client_wolfssl_failures": result.wolfssl_failures,
        "client_heap_current_bytes": result.heap_current_bytes,
        "client_heap_peak_bytes": result.heap_peak_bytes,
        "client_cpu_cycles": result.client_cpu_cycles,
        "client_cycle_hz": result.client_cycle_hz,
        "client_thread_analyzer_cpu_pct": (
            result.thread_analyzer_cpu_pct if result.thread_analyzer_cpu_pct is not None else ""
        ),
        "client_thread_max_cpu_pct": result.thread_max_cpu_pct,
        "client_thread_max_stack_used_bytes": result.thread_max_stack_used_bytes,
        "client_thread_max_stack_pct": result.thread_max_stack_pct,
        "client_ram_total_bytes": result.ram_total_bytes,
        "client_rom_total_bytes": result.rom_total_bytes,
    })


def summarize_case(case: BenchmarkCase, runs: list[RunResult]) -> dict[str, object]:
    successes = [run for run in runs if run.status == "SUCCESS"]
    failures = [run for run in runs if run.status == "FAIL"]
    timeouts = [run for run in runs if run.status == "TIMEOUT"]

    handshake_values = [run.handshake_ms for run in successes if run.handshake_ms is not None]
    raw_values = [run.raw_handshake_ms for run in successes if run.raw_handshake_ms is not None]
    full_values = [run.full_connect_ms for run in successes if run.full_connect_ms is not None]
    client_cpu_ms_values = [
        (run.client_cpu_cycles / run.client_cycle_hz) * 1000.0
        for run in successes
        if run.client_cpu_cycles and run.client_cycle_hz
    ]
    client_cpu_pct_values = [
        ((run.client_cpu_cycles / run.client_cycle_hz) * 1000.0 / run.raw_handshake_ms) * 100.0
        for run in successes
        if run.client_cpu_cycles and run.client_cycle_hz and run.raw_handshake_ms
    ]
    thread_analyzer_cpu_pct_values = [
        float(run.thread_analyzer_cpu_pct)
        for run in successes
        if run.thread_analyzer_cpu_pct is not None
    ]

    if len(successes) == len(runs):
        status = "SUCCESS"
    elif successes:
        status = "MIXED"
    elif timeouts and not failures:
        status = "TIMEOUT"
    else:
        status = "FAIL"

    mean_handshake = mean(handshake_values)
    mean_raw = mean(raw_values)
    mean_full = mean(full_values)

    return {
        "case_id": case.case_id,
        "kex_group": case.kem.name,
        "kex_nist_level": case.kem.nist_level,
        "kex_public_key_bytes": case.kem.public_key_bytes,
        "kex_ciphertext_bytes": case.kem.ciphertext_bytes,
        "kex_shared_secret_bytes": case.kem.shared_secret_bytes,
        "family": case.kem.family,
        "cert_sig_alg": case.sig.name,
        "sig_nist_level": case.sig.nist_level,
        "sig_public_key_bytes": case.sig.public_key_bytes,
        "sig_private_key_bytes": case.sig.private_key_bytes,
        "sig_signature_bytes": case.sig.signature_bytes,
        "family": case.sig.family,
        "status": status,
        "success_count": len(successes),
        "fail_count": len(failures),
        "timeout_count": len(timeouts),
        "mean_handshake_ms": fmt(mean_handshake),
        "median_handshake_ms": fmt(median(handshake_values)),
        "p95_handshake_ms": fmt(percentile_95(handshake_values)),
        "min_handshake_ms": fmt(min(handshake_values) if handshake_values else None),
        "max_handshake_ms": fmt(max(handshake_values) if handshake_values else None),
        "stddev_handshake_ms": fmt(stddev(handshake_values)),
        "handshake_throughput_hps": fmt(1000.0 / mean_handshake if mean_handshake else None),
        "mean_raw_handshake_ms": fmt(mean_raw),
        "median_raw_handshake_ms": fmt(median(raw_values)),
        "p95_raw_handshake_ms": fmt(percentile_95(raw_values)),
        "min_raw_handshake_ms": fmt(min(raw_values) if raw_values else None),
        "max_raw_handshake_ms": fmt(max(raw_values) if raw_values else None),
        "stddev_raw_handshake_ms": fmt(stddev(raw_values)),
        "raw_handshake_throughput_hps": fmt(1000.0 / mean_raw if mean_raw else None),
        "mean_full_connect_ms": fmt(mean_full),
        "connections_per_second": fmt(1000.0 / mean_full if mean_full else None),
        "mean_client_cpu_ms": fmt(mean(client_cpu_ms_values)),
        "mean_client_cpu_pct": fmt(
            mean(thread_analyzer_cpu_pct_values)
            if thread_analyzer_cpu_pct_values
            else mean(client_cpu_pct_values)
        ),
        "mean_client_thread_analyzer_cpu_pct": fmt(mean(thread_analyzer_cpu_pct_values)),
        "max_client_thread_cpu_pct": max((run.thread_max_cpu_pct for run in runs), default=0),
        "max_client_thread_stack_used_bytes": max(
            (run.thread_max_stack_used_bytes for run in runs), default=0
        ),
        "max_client_thread_stack_pct": max((run.thread_max_stack_pct for run in runs), default=0),
        "max_client_wolfssl_peak_bytes": max((run.wolfssl_peak_bytes for run in runs), default=0),
        "max_client_wolfssl_failures": max((run.wolfssl_failures for run in runs), default=0),
        "max_client_heap_current_bytes": max((run.heap_current_bytes for run in runs), default=0),
        "max_client_heap_peak_bytes": max((run.heap_peak_bytes for run in runs), default=0),
        "client_ram_total_bytes": max((run.ram_total_bytes for run in runs), default=0),
        "client_rom_total_bytes": max((run.rom_total_bytes for run in runs), default=0),
    }


def append_case_summary(case: BenchmarkCase, runs: list[RunResult]) -> None:
    summary = summarize_case(case, runs)
    append_csv_row(RESULTS_CSV, RESULT_FIELDS, summary)
    print(f"[DATA] Summary saved to {RESULTS_CSV}")


# ---------------------------------------------------------------------------
# Main benchmark loop
# ---------------------------------------------------------------------------


def selected_cases() -> list[BenchmarkCase]:
    all_cases = [BenchmarkCase(kem, sig) for kem in KEMS for sig in SIGS]
    requested = os.environ.get("PQC_BENCHMARKS")
    if not requested:
        return all_cases

    wanted = {name.strip() for name in requested.split(",") if name.strip()}
    cases = [case for case in all_cases if case.case_id in wanted]
    missing = wanted - {case.case_id for case in cases}
    if missing:
        die(f"Unknown PQC_BENCHMARKS case(s): {', '.join(sorted(missing))}")
    return cases


def prepare_case(case: BenchmarkCase) -> None:
    generate_certificates(case)
    update_nrf_certificate_headers()
    write_openssl_conf(case)
    write_mosquitto_conf()
    deploy_pi_assets()
    build_and_flash(case)


def run_case(case: BenchmarkCase) -> None:
    print("\n========================================================")
    print(f"🚀 RUNNING BENCHMARK: {case.case_id}")
    print("========================================================")

    prepare_case(case)
    ser = open_serial_port()
    runs: list[RunResult] = []
    try:
        for run_index in range(1, RUNS_PER_CASE + 1):
            runs.append(run_single_handshake(case, ser, run_index))
            if run_index < RUNS_PER_CASE:
                print(f"[COOLDOWN] Waiting {RADIO_COOLDOWN_S:g}s before next run...")
                time.sleep(RADIO_COOLDOWN_S)
    finally:
        ser.close()
        stop_pi_services()

    append_case_summary(case, runs)
    print(f"✅ {case.case_id} complete.")


def main() -> None:
    ensure_docker_running()
    ensure_pqc_image()
    ensure_raspberry_pi_ready()
    stop_pi_services()

    cases = selected_cases()
    print(f"[INFO] Running {len(cases)} case(s), {RUNS_PER_CASE} run(s) per case.")

    try:
        for case in cases:
            run_case(case)
            print(f"[COOLDOWN] Waiting {RADIO_COOLDOWN_S:g}s before next case...\n")
            time.sleep(RADIO_COOLDOWN_S)
    finally:
        stop_pi_services()


if __name__ == "__main__":
    main()
