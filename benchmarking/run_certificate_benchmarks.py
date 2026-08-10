#!/usr/bin/env python3
"""Benchmark certificate-chain generation and validation independently of TLS."""

from __future__ import annotations

import argparse
import csv
import os
import re
import shlex
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from benchmarklib.algorithms import SIGNATURES_BY_NAME, Signature, slug
from benchmarklib.certificates import (
    CERT_NOT_AFTER,
    CERT_NOT_BEFORE,
    IMAGE,
    ensure_image,
)
from benchmarklib.gateway import PiGateway
from benchmarklib.server_backends import HASH_BASED_SIGNATURES
from generate_cases import FIELDS as INPUT_FIELDS
from run_benchmarks import (
    DEFAULT_CONFIG,
    DEFAULT_NCS_VERSION,
    default_ncs_chdir,
    default_nrfutil,
    load_config,
    resolve_pi_workdir,
    resolve_serial_device,
)
from run_board_certificate_benchmark import run_board_client_certificate_benchmark


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
WORK = ROOT / "work"
WOLFSSL_COMPAT_CFLAGS = (
    "-DFP_MAX_BITS=32768 -DRSA_MAX_SIZE=16384 -DWC_MAX_RSA_BITS=16384"
)
PHASES = ["keygen", "make_cert", "sign_cert", "parse_cert", "key_export"]
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
SERVER_RESOURCE_METRICS = [
    "voluntary_context_switches", "involuntary_context_switches",
    "minor_page_faults", "major_page_faults",
    "block_input_ops", "block_output_ops",
]
SERVER_PHASES = [
    ("keygen", "Keygen"),
    ("sign_cert", "Sign cert"),
    ("verify_cert", "Verify cert"),
]
SERVER_PHASE_TIME_METRICS = [
    "wall_ms", "cpu_ms", "user_cpu_ms", "sys_cpu_ms",
]
SERVER_PHASE_ATTEMPT_FIELDS = [
    field
    for phase, _label in SERVER_PHASES
    for field in (
        *[
            f"server_{phase}_{metric}"
            for metric in SERVER_PHASE_TIME_METRICS
        ],
        f"server_{phase}_rss_kb",
        *[
            f"server_{phase}_{metric}"
            for metric in SERVER_RESOURCE_METRICS
        ],
    )
]
SERVER_PHASE_SUMMARY_FIELDS = [
    field
    for phase, _label in SERVER_PHASES
    for field in (
        *[
            f"mean_server_{phase}_{metric}"
            for metric in SERVER_PHASE_TIME_METRICS
        ],
        f"max_server_{phase}_rss_kb",
        *[
            f"mean_server_{phase}_{metric}"
            for metric in SERVER_RESOURCE_METRICS
        ],
    )
]

ATTEMPT_FIELDS = [
    "attempt_index", "component", "owner", "cert_sig_alg", "sig_family",
    "sig_nist_level", "builder", "generation_scope", "status",
    "wall_ms", "cpu_ms", "user_cpu_ms", "sys_cpu_ms", "max_rss_kb",
    "server_root_der_bytes", "server_root_crt_bytes",
    "server_intermediate_crt_bytes", "server_leaf_crt_bytes",
    "server_chain_crt_bytes", "server_key_bytes",
    "client_ca_crt_bytes", "client_cert_crt_bytes", "client_key_bytes",
    "client_csr_der_bytes", "client_csr_pem_bytes", "output_total_bytes",
    "client_cpu_ms", "client_cpu_cycles", "client_cycle_hz",
    "client_cpu_usage_percent", "system_cpu_usage_percent",
    "thread_main_cpu_percent", "thread_sysworkq_cpu_percent",
    "thread_bt_rx_cpu_percent", "thread_bt_tx_cpu_percent",
    "thread_idle_cpu_percent", "thread_other_cpu_percent",
    "keygen_cpu_ms", "make_cert_cpu_ms", "sign_cert_cpu_ms",
    "parse_cert_cpu_ms", "key_export_cpu_ms", "phase_cpu_total_ms",
    "phase_cpu_verify",
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
    "client_heap_current_bytes", "client_heap_peak_bytes",
    "client_heap_free_bytes", "client_heap_capacity_bytes",
    "thread_stack_used_bytes", "thread_stack_capacity_bytes",
    "thread_stack_peak_percent", "client_cert_der_bytes",
    "client_key_der_bytes", "client_cert_der_capacity_bytes",
    "client_key_der_capacity_bytes", "client_hbs_state_capacity_bytes",
    "error_code", "message",
    *SERVER_RESOURCE_METRICS,
    *SERVER_PHASE_ATTEMPT_FIELDS,
    *[
        f"{phase}_{counter}_{suffix}"
        for counter, suffix in ADDED_PHASE_DWT_METRICS
        for phase in PHASES
    ],
    *[
        f"phase_{counter}_total_{suffix}"
        for counter, suffix in ADDED_PHASE_DWT_METRICS
    ],
    "firmware_static_ram_used_bytes", "firmware_ram_capacity_bytes",
    "firmware_static_ram_usage_percent",
]

SUMMARY_FIELDS = [
    "component", "owner", "cert_sig_alg", "sig_family", "sig_nist_level",
    "builder", "generation_scope", "status", "success_count", "fail_count",
    "mean_wall_ms", "min_wall_ms", "max_wall_ms",
    "mean_cpu_ms", "mean_user_cpu_ms", "mean_sys_cpu_ms",
    "max_rss_kb", "mean_output_total_bytes",
    "server_chain_crt_bytes", "server_key_bytes",
    "client_cert_crt_bytes", "client_key_bytes",
    "client_csr_der_bytes", "client_csr_pem_bytes",
    "mean_client_cpu_ms", "mean_thread_main_cpu_percent",
    "mean_thread_sysworkq_cpu_percent", "mean_thread_bt_rx_cpu_percent",
    "mean_thread_bt_tx_cpu_percent", "mean_thread_idle_cpu_percent",
    "mean_thread_other_cpu_percent", "max_client_heap_peak_bytes",
    "mean_keygen_cpu_ms", "mean_make_cert_cpu_ms",
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
    "dwt_counters_supported", "dwt_wrap_risk",
    "max_thread_stack_peak_percent", "client_cert_der_bytes",
    "client_key_der_bytes",
    *[f"mean_{metric}" for metric in SERVER_RESOURCE_METRICS],
    *SERVER_PHASE_SUMMARY_FIELDS,
    "firmware_static_ram_used_bytes", "firmware_ram_capacity_bytes",
    "firmware_static_ram_usage_percent",
    *[
        f"mean_{phase}_{counter}_{suffix}"
        for counter, suffix in ADDED_PHASE_DWT_METRICS
        for phase in PHASES
    ],
    *[
        f"mean_phase_{counter}_total_{suffix}"
        for counter, suffix in ADDED_PHASE_DWT_METRICS
    ],
]

MEASURE_EXEC_C = r"""
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static long long timeval_us(struct timeval tv)
{
    return (long long)tv.tv_sec * 1000000LL + tv.tv_usec;
}

static long long elapsed_us(struct timespec start, struct timespec end)
{
    return (long long)(end.tv_sec - start.tv_sec) * 1000000LL +
           (end.tv_nsec - start.tv_nsec) / 1000LL;
}

int main(int argc, char** argv)
{
    struct timespec start;
    struct timespec end;
    struct rusage usage;
    int status = 0;
    pid_t pid;
    int exit_code;

    if (argc < 2) {
        fprintf(stderr, "usage: measure_exec COMMAND [ARGS...]\n");
        return 2;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        perror("clock_gettime");
        return 2;
    }
    pid = fork();
    if (pid < 0) {
        perror("fork");
        return 2;
    }
    if (pid == 0) {
        execvp(argv[1], &argv[1]);
        fprintf(stderr, "execvp(%s): %s\n", argv[1], strerror(errno));
        _exit(127);
    }
    if (wait4(pid, &status, 0, &usage) < 0) {
        perror("wait4");
        return 2;
    }
    if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) {
        perror("clock_gettime");
        return 2;
    }
    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    }
    else if (WIFSIGNALED(status)) {
        exit_code = 128 + WTERMSIG(status);
    }
    else {
        exit_code = 2;
    }
    printf("[CERT_BENCH] status=%d wall_us=%lld user_cpu_us=%lld "
           "sys_cpu_us=%lld cpu_us=%lld max_rss_kb=%ld "
           "voluntary_context_switches=%ld involuntary_context_switches=%ld "
           "minor_page_faults=%ld major_page_faults=%ld "
           "block_input_ops=%ld block_output_ops=%ld\n",
           exit_code, elapsed_us(start, end), timeval_us(usage.ru_utime),
           timeval_us(usage.ru_stime),
           timeval_us(usage.ru_utime) + timeval_us(usage.ru_stime),
           usage.ru_maxrss, usage.ru_nvcsw, usage.ru_nivcsw,
           usage.ru_minflt, usage.ru_majflt, usage.ru_inblock,
           usage.ru_oublock);
    fflush(stdout);
    return exit_code;
}
"""


def write_csv(path: Path, fields: list[str], rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def read_cases(path: Path) -> list[dict[str, str]]:
    with path.open(newline="") as stream:
        reader = csv.DictReader(stream)
        missing = set(INPUT_FIELDS) - set(reader.fieldnames or ())
        if missing:
            raise ValueError(f"case CSV is missing fields: {', '.join(sorted(missing))}")
        rows = [
            dict(row) for row in reader
            if row.get("enabled", "").lower() in {"1", "true", "yes"}
        ]
    if not rows:
        raise ValueError("case CSV has no enabled cases")
    for row in rows:
        if row["cert_sig_alg"] not in SIGNATURES_BY_NAME:
            raise ValueError(f"{row['case_id']}: unknown signature {row['cert_sig_alg']}")
    return rows


def signature_cases(cases: list[dict[str, str]]) -> list[dict[str, str]]:
    selected: dict[str, dict[str, str]] = {}
    for case in cases:
        selected.setdefault(case["cert_sig_alg"], case)
    return [selected[name] for name in sorted(selected)]


def parse_cert_bench(output: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in output.splitlines():
        if line.startswith("[CERT_PHASE]"):
            tokens: dict[str, str] = {}
            for token in line.removeprefix("[CERT_PHASE]").strip().split():
                if "=" in token:
                    key, value = token.split("=", 1)
                    tokens[key] = value
            phase = tokens.get("name", "")
            if phase not in {name for name, _label in SERVER_PHASES}:
                continue
            prefix = f"server_{phase}"
            for key, value in tokens.items():
                if key in {"name", "status"}:
                    continue
                values[f"{prefix}_{key}"] = value
            continue
        if not line.startswith("[CERT_BENCH]"):
            continue
        for token in line.removeprefix("[CERT_BENCH]").strip().split():
            if "=" in token:
                key, value = token.split("=", 1)
                values[key] = value
    return values


def ms(values: dict[str, str], key: str) -> str:
    try:
        return f"{float(values[key]) / 1000.0:.3f}"
    except (KeyError, ValueError):
        return ""


def server_phase_attempt_values(metrics: dict[str, str]) -> dict[str, object]:
    values: dict[str, object] = {}
    for phase, _label in SERVER_PHASES:
        prefix = f"server_{phase}"
        for metric in SERVER_PHASE_TIME_METRICS:
            source = f"{prefix}_{metric.removesuffix('_ms')}_us"
            values[f"{prefix}_{metric}"] = ms(metrics, source)
        values[f"{prefix}_rss_kb"] = metrics.get(f"{prefix}_max_rss_kb", "")
        for metric in SERVER_RESOURCE_METRICS:
            values[f"{prefix}_{metric}"] = metrics.get(f"{prefix}_{metric}", "")
    return values


def usage_percent(values: dict[str, object], used_key: str, capacity_key: str) -> str:
    try:
        used = float(values.get(used_key, ""))
        capacity = float(values.get(capacity_key, ""))
    except (TypeError, ValueError):
        return ""
    if capacity <= 0:
        return ""
    return f"{100.0 * used / capacity:.2f}"


def file_size(path: Path) -> int:
    return path.stat().st_size if path.exists() else 0


def total_size(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())


def run_measured_container(
    output: Path,
    script: str,
    log: Path,
    *,
    mounts: list[tuple[Path, str, bool]] | None = None,
    setup_script: str = "",
) -> tuple[int, dict[str, str], str]:
    output.mkdir(parents=True, exist_ok=True)
    wrapper = f"""
set -eu
cat > /tmp/measure_exec.c <<'MEASURE_C'
{MEASURE_EXEC_C}
MEASURE_C
cc -O2 -Wall -Wextra -o /tmp/measure_exec /tmp/measure_exec.c
{setup_script.rstrip()}
cat > /tmp/cert_bench.sh <<'CERT_SCRIPT'
{script.rstrip()}
CERT_SCRIPT
chmod +x /tmp/cert_bench.sh
/tmp/measure_exec /bin/sh /tmp/cert_bench.sh
"""
    command = [
        "docker", "run", "--rm",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "-v", f"{output.resolve()}:/out",
    ]
    for source, destination, readonly in mounts or []:
        suffix = ":ro" if readonly else ""
        command.extend(["-v", f"{source.resolve()}:{destination}{suffix}"])
    command.extend([IMAGE, "sh", "-ec", wrapper])
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a") as stream:
        stream.write(f"$ {' '.join(shlex.quote(part) for part in command)}\n")
        proc = subprocess.run(
            command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        stream.write(proc.stdout)
    return proc.returncode, parse_cert_bench(proc.stdout), proc.stdout


def key_args(key_type: str) -> str:
    ecdsa_curves = {
        "ECDSA-P-256": "prime256v1",
        "ECDSA-P-384": "secp384r1",
        "ECDSA-P-521": "secp521r1",
    }
    match = re.fullmatch(r"RSA-PSS-(\d+)", key_type)
    if match:
        return f"-newkey rsa:{match.group(1)}"
    if key_type in ecdsa_curves:
        return f"-newkey ec -pkeyopt ec_paramgen_curve:{ecdsa_curves[key_type]}"
    if key_type.startswith("ec:"):
        return f"-newkey ec -pkeyopt ec_paramgen_curve:{key_type.split(':', 1)[1]}"
    return f"-newkey {key_type}"


def hash_arg(key_type: str) -> str:
    match = re.fullmatch(r"RSA-PSS-(\d+)", key_type)
    if not match:
        return ""
    bits = int(match.group(1))
    return "-sha256" if bits <= 3072 else "-sha384" if bits <= 7680 else "-sha512"


def rsa_pss_sigopts(key_type: str) -> str:
    match = re.fullmatch(r"RSA-PSS-(\d+)", key_type)
    if not match:
        return ""
    bits = int(match.group(1))
    hash_name = "sha256" if bits <= 3072 else "sha384" if bits <= 7680 else "sha512"
    salt_len = 32 if bits <= 3072 else 48 if bits <= 7680 else 64
    return (
        "-sigopt rsa_padding_mode:pss "
        f"-sigopt rsa_mgf1_md:{hash_name} "
        f"-sigopt rsa_pss_saltlen:{salt_len}"
    )


SERVER_PHASE_SHELL = r"""
cert_phase() {
  phase_name="$1"
  shift
  phase_output="$(mktemp "${TMPDIR:-/tmp}/cert-phase.XXXXXX")"
  measure_exec "$@" >"$phase_output" 2>&1
  phase_rc=$?
  cat "$phase_output"
  awk -v name="$phase_name" '
    /^\[CERT_BENCH\]/ {
      sub(/^\[CERT_BENCH\] /, "[CERT_PHASE] name=" name " ")
      print
    }
  ' "$phase_output"
  rm -f "$phase_output"
  return "$phase_rc"
}
"""


def server_phase_command(phase: str, command: str) -> str:
    measured = f"cert_phase {shlex.quote(phase)} /bin/sh -c {shlex.quote(command)}"
    return f"{measured} || exit $?"


class PiCertificateRunner:
    def __init__(self, host: str, workdir: str, ssh_key: str, run_id: str) -> None:
        self.gateway = PiGateway(host, workdir, ssh_key)
        self.remote_run_dir = f"{workdir.rstrip('/')}/certgen/{slug(run_id)}"
        self._prepared_roots: set[str] = set()

    def start(self, log: Path) -> None:
        self.gateway.start_master(log)

    def stop(self) -> None:
        self.gateway.stop_master()

    def prepare(self, log: Path, builders: set[str]) -> None:
        workdir = shlex.quote(self.gateway.workdir)
        warmup_dir = shlex.quote(f"{self.remote_run_dir}/warmup/openssl")
        hbs_warmup_dir = shlex.quote(f"{self.remote_run_dir}/warmup/hbs")
        self.gateway.command(
            f"""
set -eu
mkdir -p {workdir}/bin {workdir}/certgen {workdir}/logs {workdir}/deps
cat > {workdir}/bin/measure_exec.c <<'MEASURE_C'
{MEASURE_EXEC_C}
MEASURE_C
cat > {workdir}/bin/openssl-oqs.cnf <<'OPENSSL_OQS_CONF'
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
oqsprovider = oqsprovider_sect

[default_sect]
activate = 1

[oqsprovider_sect]
activate = 1
module = /usr/local/lib/ossl-modules/oqsprovider.so
OPENSSL_OQS_CONF
cd {workdir}
gcc -O2 -Wall -Wextra -o bin/measure_exec bin/measure_exec.c
OPENSSL_CONF="$PWD/bin/openssl-oqs.cnf" \\
  OPENSSL_MODULES=/usr/local/lib/ossl-modules \\
  openssl list -providers | grep -q oqsprovider
mkdir -p {warmup_dir}
export OPENSSL_CONF="$PWD/bin/openssl-oqs.cnf"
export OPENSSL_MODULES=/usr/local/lib/ossl-modules
openssl list -signature-algorithms >/dev/null
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \\
  -keyout {warmup_dir}/root.key -out {warmup_dir}/root.crt -nodes \\
  -subj /CN=Peripheral_Benchmark_Warmup_Root \\
  -not_before {CERT_NOT_BEFORE} -not_after {CERT_NOT_AFTER} \\
  -addext basicConstraints=critical,CA:TRUE \\
  -addext keyUsage=critical,keyCertSign,cRLSign >/dev/null 2>&1
openssl x509 -in {warmup_dir}/root.crt -outform DER \\
  -out {warmup_dir}/root.der
printf 'basicConstraints=critical,CA:FALSE\\nkeyUsage=critical,digitalSignature,keyEncipherment\\nextendedKeyUsage=critical,serverAuth\\nsubjectAltName=DNS:localhost,IP:127.0.0.1\\n' \\
  > {warmup_dir}/server.ext
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \\
  -keyout {warmup_dir}/server.key -out {warmup_dir}/server.csr \\
  -nodes -subj /CN=localhost >/dev/null 2>&1
openssl x509 -req -in {warmup_dir}/server.csr -CA {warmup_dir}/root.crt \\
  -CAkey {warmup_dir}/root.key -CAcreateserial -out {warmup_dir}/server.crt \\
  -not_before {CERT_NOT_BEFORE} -not_after {CERT_NOT_AFTER} \\
  -extfile {warmup_dir}/server.ext >/dev/null 2>&1
openssl verify -purpose sslserver -CAfile {warmup_dir}/root.crt \\
  {warmup_dir}/server.crt >/dev/null
cat {warmup_dir}/root.crt {warmup_dir}/root.key {warmup_dir}/root.der \\
  {warmup_dir}/server.crt {warmup_dir}/server.key >/dev/null
""",
            log,
        )
        if not ({"wolfssl", "wolfssl-hbs"} & builders):
            return
        self.gateway.deploy_file(
            ROOT / "tools" / "hbs_certgen.c",
            f"{self.gateway.workdir}/bin/hbs_certgen.c",
            log,
        )
        self.gateway.deploy_file(
            ROOT / "tools" / "wolfssl_certgen.c",
            f"{self.gateway.workdir}/bin/wolfssl_certgen.c",
            log,
        )
        self.gateway.deploy_file(
            ROOT / "gateway" / "setup_pi_wolfssl.sh",
            f"{self.gateway.workdir}/bin/setup_pi_wolfssl.sh",
            log,
        )
        self.gateway.command(
            f"""
set -eu
cd {workdir}
chmod +x bin/setup_pi_wolfssl.sh
./bin/setup_pi_wolfssl.sh deps/wolfssl
export PKG_CONFIG_PATH="$PWD/deps/wolfssl/lib/pkgconfig"
pkg-config --exists wolfssl
gcc -O2 -Wall -Wextra \\
  -DWOLFSSL_HAVE_LMS -DWOLFSSL_HAVE_XMSS {WOLFSSL_COMPAT_CFLAGS} \\
  -o bin/hbs_certgen bin/hbs_certgen.c \\
  $(pkg-config --cflags --libs wolfssl) \\
  -Wl,-rpath,"$PWD/deps/wolfssl/lib"
gcc -O2 -Wall -Wextra {WOLFSSL_COMPAT_CFLAGS} \\
  -o bin/wolfssl_certgen bin/wolfssl_certgen.c \\
  $(pkg-config --cflags --libs wolfssl) \\
  -Wl,-rpath,"$PWD/deps/wolfssl/lib"
test -x bin/hbs_certgen
test -x bin/wolfssl_certgen
bin/hbs_certgen >/dev/null 2>&1 || true
bin/wolfssl_certgen >/dev/null 2>&1 || true
cat bin/hbs_certgen bin/wolfssl_certgen deps/wolfssl/lib/libwolfssl.so* \\
  >/dev/null 2>&1 || true
mkdir -p {hbs_warmup_dir}/lms
bin/hbs_certgen LMS-HSS-L2-H10-W4 {hbs_warmup_dir}/lms >/dev/null 2>&1 || true
""",
            log,
        )

    def command_capture(
        self,
        script: str,
        log: Path,
        *,
        check: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            *self.gateway.ssh_base(),
            self.gateway.host,
            f"bash -lc {shlex.quote(script)}",
        ]
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("a") as stream:
            stream.write(f"$ remote: {script}\n")
            proc = subprocess.run(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
            )
            stream.write(proc.stdout)
        if check and proc.returncode:
            raise subprocess.CalledProcessError(proc.returncode, command)
        return proc

    def copy_from(self, remote_dir: str, destination: Path, log: Path) -> None:
        destination.mkdir(parents=True, exist_ok=True)
        ssh_transport = " ".join(shlex.quote(part) for part in self.gateway.ssh_base())
        command = [
            "rsync", "-a", "-e", ssh_transport,
            f"{self.gateway.host}:{remote_dir.rstrip('/')}/",
            f"{destination}/",
        ]
        with log.open("a") as stream:
            stream.write(f"$ {' '.join(shlex.quote(part) for part in command)}\n")
            proc = subprocess.run(command, text=True, stdout=stream, stderr=subprocess.STDOUT)
        if proc.returncode:
            raise subprocess.CalledProcessError(proc.returncode, command)

    def remote_attempt_dir(
        self, signature: Signature, builder: str, attempt: int
    ) -> str:
        return (
            f"{self.remote_run_dir}/attempts/"
            f"{slug(signature.name)}/{slug(builder)}/{attempt:03d}"
        )

    def remote_root_dir(self, signature: Signature) -> str:
        return f"{self.remote_run_dir}/roots/{slug(signature.issuer_key_type)}"

    def ensure_server_root(
        self,
        signature: Signature,
        local_dir: Path,
        log: Path,
    ) -> str:
        remote_dir = self.remote_root_dir(signature)
        if remote_dir in self._prepared_roots:
            return remote_dir
        issuer_args = key_args(signature.issuer_key_type)
        issuer_hash = hash_arg(signature.issuer_key_type)
        issuer_sigopts = rsa_pss_sigopts(signature.issuer_key_type)
        root_name = f"Peripheral_Benchmark_{slug(signature.name)}_Server_Root"
        qremote = shlex.quote(remote_dir)
        qworkdir = shlex.quote(self.gateway.workdir)
        self.command_capture(
            f"""
set -eu
mkdir -p {qremote}
cd {qworkdir}
export OPENSSL_CONF="$PWD/bin/openssl-oqs.cnf"
export OPENSSL_MODULES=/usr/local/lib/ossl-modules
if [ -s {qremote}/server_root.crt ] \\
   && [ -s {qremote}/server_root.key ] \\
   && [ -s {qremote}/server_root.der ]; then
  exit 0
fi
openssl req -x509 -new {issuer_args} \\
  -keyout {qremote}/server_root.key -out {qremote}/server_root.crt -nodes \\
  -subj /CN={root_name} \\
  -not_before {CERT_NOT_BEFORE} -not_after {CERT_NOT_AFTER} \\
  {issuer_hash} {issuer_sigopts} \\
  -addext basicConstraints=critical,CA:TRUE \\
  -addext keyUsage=critical,keyCertSign,cRLSign
openssl x509 -in {qremote}/server_root.crt -outform DER \\
  -out {qremote}/server_root.der
openssl x509 -in {qremote}/server_root.crt -noout >/dev/null
cat {qremote}/server_root.crt {qremote}/server_root.key \\
  {qremote}/server_root.der >/dev/null
""",
            log,
            check=True,
        )
        self.copy_from(remote_dir, local_dir, log)
        self._prepared_roots.add(remote_dir)
        return remote_dir

    def run_measured(
        self,
        output: Path,
        remote_output: str,
        script: str,
        log: Path,
    ) -> tuple[int, dict[str, str], str]:
        qout = shlex.quote(remote_output)
        qscript = shlex.quote(f"{remote_output}/cert_bench.sh")
        qworkdir = shlex.quote(self.gateway.workdir)
        proc = self.command_capture(
            f"""
set -eu
mkdir -p {qout}
cat > {qscript} <<'CERT_SCRIPT'
{script.rstrip()}
CERT_SCRIPT
chmod +x {qscript}
cd {qworkdir}
export PATH="$PWD/bin:$PATH"
export OPENSSL_CONF="$PWD/bin/openssl-oqs.cnf"
export OPENSSL_MODULES=/usr/local/lib/ossl-modules
export PKG_CONFIG_PATH="$PWD/deps/wolfssl/lib/pkgconfig"
export LD_LIBRARY_PATH="$PWD/deps/wolfssl/lib:${{LD_LIBRARY_PATH:-}}"
bin/measure_exec /bin/sh {qscript}
""",
            log,
        )
        self.copy_from(remote_output, output, log)
        return proc.returncode, parse_cert_bench(proc.stdout), proc.stdout


WOLFSSL_CLIENT_IDENTITY_C = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>

#define DER_CAP 4096
#define KEY_CAP 2048
#define CERT_NOT_BEFORE "\x18\x0f""20200101000000Z"
#define CERT_NOT_AFTER  "\x18\x0f""20360101000000Z"

static int write_file(const char* path, const unsigned char* data, int len)
{
    FILE* f = fopen(path, "wb");
    if (f == NULL)
        return -1;
    if (fwrite(data, 1, (size_t)len, f) != (size_t)len) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int write_pem_csr(const char* path, const unsigned char* der, int derSz)
{
    unsigned char pem[DER_CAP * 2];
    int pemSz = wc_DerToPem(der, derSz, pem, sizeof(pem), CERTREQ_TYPE);
    if (pemSz <= 0)
        return pemSz;
    return write_file(path, pem, pemSz);
}

static int write_pem_key(const char* path, const unsigned char* der, int derSz)
{
    unsigned char pem[KEY_CAP * 2];
    int pemSz = wc_DerToPem(der, derSz, pem, sizeof(pem), ECC_PRIVATEKEY_TYPE);
    if (pemSz <= 0)
        return pemSz;
    return write_file(path, pem, pemSz);
}

static void set_fixed_validity(Cert* cert)
{
    XMEMCPY(cert->beforeDate, CERT_NOT_BEFORE, sizeof(CERT_NOT_BEFORE) - 1);
    cert->beforeDateSz = sizeof(CERT_NOT_BEFORE) - 1;
    XMEMCPY(cert->afterDate, CERT_NOT_AFTER, sizeof(CERT_NOT_AFTER) - 1);
    cert->afterDateSz = sizeof(CERT_NOT_AFTER) - 1;
}

static void set_client_name(Cert* cert)
{
    XSTRNCPY(cert->subject.country, "US", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.state, "OR", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.locality, "Portland", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.org, "Peripheral Benchmark", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.unit, "TLS Client", CTC_NAME_SIZE);
    XSTRNCPY(cert->subject.commonName, "nrf52840-benchmark", CTC_NAME_SIZE);
}

static int make_client_request(ecc_key* clientKey, WC_RNG* rng,
    unsigned char* csrDer)
{
    Cert request;
    int bodySz;

    if (wc_InitCert(&request) != 0)
        return -1;
    set_client_name(&request);
    set_fixed_validity(&request);
    request.sigType = CTC_SHA256wECDSA;
    bodySz = wc_MakeCertReq_ex(&request, csrDer, DER_CAP, ECC_TYPE, clientKey);
    if (bodySz <= 0)
        return -1;
    return wc_SignCert_ex(bodySz, CTC_SHA256wECDSA, csrDer, DER_CAP,
        ECC_TYPE, clientKey, rng);
}

static int verify_client_request(const unsigned char* csrDer, int csrSz)
{
    DecodedCert decoded;
    int ret;

    wc_InitDecodedCert(&decoded, csrDer, (word32)csrSz, NULL);
    ret = wc_ParseCert(&decoded, CERTREQ_TYPE, VERIFY, NULL);
    wc_FreeDecodedCert(&decoded);
    return ret;
}

int main(int argc, char** argv)
{
    char path[1024];
    unsigned char clientCsrDer[DER_CAP];
    unsigned char clientKeyDer[KEY_CAP];
    int clientCsrSz;
    int clientKeySz;
    int ret = 1;
    const char* outdir;
    WC_RNG rng;
    ecc_key clientKey;

    if (argc != 2) {
        fprintf(stderr, "usage: %s OUTDIR\n", argv[0]);
        return 2;
    }
    outdir = argv[1];

    wolfSSL_Init();
    if (wc_InitRng(&rng) != 0)
        goto cleanup_ssl;
    if (wc_ecc_init(&clientKey) != 0)
        goto cleanup_rng;
    if (wc_ecc_make_key(&rng, 32, &clientKey) != 0)
        goto cleanup_client;

    clientCsrSz = make_client_request(&clientKey, &rng, clientCsrDer);
    if (clientCsrSz <= 0)
        goto cleanup_client;
    if (verify_client_request(clientCsrDer, clientCsrSz) != 0)
        goto cleanup_client;
    clientKeySz = wc_EccKeyToDer(&clientKey, clientKeyDer, KEY_CAP);
    if (clientKeySz <= 0)
        goto cleanup_client;

    snprintf(path, sizeof(path), "%s/client.csr.der", outdir);
    if (write_file(path, clientCsrDer, clientCsrSz) != 0)
        goto cleanup_client;
    snprintf(path, sizeof(path), "%s/client.csr", outdir);
    if (write_pem_csr(path, clientCsrDer, clientCsrSz) != 0)
        goto cleanup_client;
    snprintf(path, sizeof(path), "%s/client_key.der", outdir);
    if (write_file(path, clientKeyDer, clientKeySz) != 0)
        goto cleanup_client;
    snprintf(path, sizeof(path), "%s/client.key", outdir);
    if (write_pem_key(path, clientKeyDer, clientKeySz) != 0)
        goto cleanup_client;

    ret = 0;

cleanup_client:
    wc_ecc_free(&clientKey);
cleanup_rng:
    wc_FreeRng(&rng);
cleanup_ssl:
    wolfSSL_Cleanup();
    return ret;
}
"""


def wolfssl_client_identity_setup_script() -> str:
    return f"""
cat > /tmp/wolfssl_client_identity.c <<'CLIENT_IDENTITY_C'
{WOLFSSL_CLIENT_IDENTITY_C}
CLIENT_IDENTITY_C
cc -O2 -Wall -Wextra -o /tmp/wolfssl_client_identity \\
  /tmp/wolfssl_client_identity.c {WOLFSSL_COMPAT_CFLAGS} \\
  $(pkg-config --cflags --libs wolfssl)
"""


def client_identity_script() -> str:
    return """
/tmp/wolfssl_client_identity /out
"""


def openssl_server_chain_script(
    signature: Signature,
    *,
    output_dir: str = "/out",
    client_dir: str = "/client",
) -> str:
    leaf_args = key_args(signature.leaf_key_type)
    issuer_hash = hash_arg(signature.issuer_key_type)
    leaf_hash = hash_arg(signature.leaf_key_type)
    issuer_sigopts = rsa_pss_sigopts(signature.issuer_key_type)
    leaf_sigopts = rsa_pss_sigopts(signature.leaf_key_type)
    out = shlex.quote(output_dir)
    client = shlex.quote(client_dir)
    setup_cmd = (
        f"cp {client}/server_root.crt {client}/server_root.key "
        f"{client}/server_root.der {out}/ && "
        "printf 'basicConstraints=critical,CA:FALSE\\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\\n"
        "extendedKeyUsage=critical,serverAuth\\n"
        "subjectAltName=DNS:localhost,IP:127.0.0.1\\n"
        "subjectKeyIdentifier=hash\\n"
        "authorityKeyIdentifier=keyid,issuer\\n' "
        f"> {out}/server.ext"
    )
    keygen_cmd = (
        f"openssl req -new {leaf_args} -keyout {out}/server.key "
        f"-out {out}/server.csr -nodes -subj /CN=localhost "
        f"{leaf_hash} {leaf_sigopts}"
    )
    sign_cmd = (
        f"openssl x509 -req -in {out}/server.csr -CA {out}/server_root.crt "
        f"-CAkey {out}/server_root.key -CAcreateserial "
        f"-out {out}/server.crt -not_before {CERT_NOT_BEFORE} "
        f"-not_after {CERT_NOT_AFTER} -extfile {out}/server.ext "
        f"{issuer_hash} {issuer_sigopts}"
    )
    assemble_cmd = f"cp {out}/server.crt {out}/server_chain.crt"
    verify_cmd = (
        f"openssl verify -purpose sslserver -CAfile {out}/server_root.crt "
        f"{out}/server.crt"
    )
    return f"""
{SERVER_PHASE_SHELL.rstrip()}
{setup_cmd}
{server_phase_command("keygen", keygen_cmd)}
{server_phase_command("sign_cert", sign_cmd)}
{assemble_cmd}
{server_phase_command("verify_cert", verify_cmd)}
"""


def hbs_server_chain_script(signature: Signature, *, output_dir: str = "/out") -> str:
    return f"hbs_certgen {shlex.quote(signature.name)} {shlex.quote(output_dir)}"


def wolfssl_server_chain_script(signature: Signature, *, output_dir: str = "/out") -> str:
    return f"wolfssl_certgen {shlex.quote(signature.name)} {shlex.quote(output_dir)}"


def wolfssl_server_builder_for(signature: Signature) -> str:
    return "wolfssl-hbs" if signature.name in HASH_BASED_SIGNATURES else "wolfssl"


def server_builders_for(signature: Signature, requested: str) -> list[str]:
    if requested == "wolfssl":
        return [wolfssl_server_builder_for(signature)]
    if requested == "openssl":
        return [] if signature.name in HASH_BASED_SIGNATURES else ["openssl"]

    builders = []
    if signature.name not in HASH_BASED_SIGNATURES:
        builders.append("openssl")
    builders.append(wolfssl_server_builder_for(signature))
    return builders


def server_generation_scope(builder: str) -> str:
    if builder == "wolfssl-hbs":
        return "hash_based_root_and_leaf"
    if builder == "wolfssl":
        return "wolfssl_root_and_leaf"
    return "leaf_under_existing_root"


def server_script_for(
    signature: Signature,
    builder: str,
    *,
    output_dir: str = "/out",
    client_dir: str = "/client",
) -> str:
    if builder == "wolfssl-hbs":
        return hbs_server_chain_script(signature, output_dir=output_dir)
    if builder == "wolfssl":
        return wolfssl_server_chain_script(signature, output_dir=output_dir)
    return openssl_server_chain_script(
        signature, output_dir=output_dir, client_dir=client_dir
    )


def attempt_row(
    *,
    attempt_index: int,
    component: str,
    owner: str,
    case: dict[str, str],
    signature: Signature,
    builder: str,
    generation_scope: str,
    output: Path,
    status: str,
    metrics: dict[str, str],
    message: str,
) -> dict[str, object]:
    return {
        "attempt_index": attempt_index,
        "component": component,
        "owner": owner,
        "cert_sig_alg": signature.name,
        "sig_family": signature.family,
        "sig_nist_level": signature.nist_level,
        "builder": builder,
        "generation_scope": generation_scope,
        "status": status,
        "wall_ms": ms(metrics, "wall_us"),
        "cpu_ms": ms(metrics, "cpu_us"),
        "user_cpu_ms": ms(metrics, "user_cpu_us"),
        "sys_cpu_ms": ms(metrics, "sys_cpu_us"),
        "max_rss_kb": metrics.get("max_rss_kb", ""),
        **{metric: metrics.get(metric, "") for metric in SERVER_RESOURCE_METRICS},
        **server_phase_attempt_values(metrics),
        "server_root_der_bytes": file_size(output / "server_root.der"),
        "server_root_crt_bytes": file_size(output / "server_root.crt"),
        "server_intermediate_crt_bytes": file_size(output / "server_intermediate.crt"),
        "server_leaf_crt_bytes": file_size(output / "server.crt"),
        "server_chain_crt_bytes": file_size(output / "server_chain.crt"),
        "server_key_bytes": file_size(output / "server.key"),
        "client_ca_crt_bytes": file_size(output / "client_ca.crt"),
        "client_cert_crt_bytes": file_size(output / "client.crt"),
        "client_key_bytes": file_size(output / "client.key"),
        "client_csr_der_bytes": file_size(output / "client.csr.der"),
        "client_csr_pem_bytes": file_size(output / "client.csr"),
        "output_total_bytes": total_size(output),
        "error_code": metrics.get("status", ""),
        "message": message,
    }


def summarize(rows: list[dict[str, object]]) -> list[dict[str, object]]:
    groups: dict[tuple[str, str, str, str], list[dict[str, object]]] = {}
    for row in rows:
        groups.setdefault((
            str(row["component"]),
            str(row["cert_sig_alg"]),
            str(row.get("builder", "")),
            str(row.get("generation_scope", "")),
        ), []).append(row)

    def numbers(items: list[dict[str, object]], field: str) -> list[float]:
        values = []
        for item in items:
            value = item.get(field, "")
            if value != "":
                values.append(float(value))
        return values

    summaries = []
    for (_component, _signature, _builder, _generation_scope), items in sorted(
        groups.items()
    ):
        success = [item for item in items if item["status"] == "success"]
        unsupported = [item for item in items if item["status"] == "unsupported"]
        failed = [
            item for item in items
            if item["status"] not in {"success", "unsupported"}
        ]
        base = items[0]
        status = "success" if len(success) == len(items) else "fail"
        if not success and len(unsupported) == len(items):
            status = "unsupported"
        wall = numbers(success, "wall_ms")
        cpu = numbers(success, "cpu_ms")
        user_cpu = numbers(success, "user_cpu_ms")
        sys_cpu = numbers(success, "sys_cpu_ms")
        rss = numbers(success, "max_rss_kb")
        server_resources = {
            metric: numbers(success, metric)
            for metric in SERVER_RESOURCE_METRICS
        }
        server_phase_values = {
            (phase, metric): numbers(success, f"server_{phase}_{metric}")
            for phase, _label in SERVER_PHASES
            for metric in SERVER_PHASE_TIME_METRICS
        }
        server_phase_rss = {
            phase: numbers(success, f"server_{phase}_rss_kb")
            for phase, _label in SERVER_PHASES
        }
        server_phase_resources = {
            (phase, metric): numbers(success, f"server_{phase}_{metric}")
            for phase, _label in SERVER_PHASES
            for metric in SERVER_RESOURCE_METRICS
        }
        output_bytes = numbers(success, "output_total_bytes")
        client_cpu = numbers(success, "client_cpu_ms")
        thread_main_cpu = numbers(success, "thread_main_cpu_percent")
        thread_sysworkq_cpu = numbers(success, "thread_sysworkq_cpu_percent")
        thread_bt_rx_cpu = numbers(success, "thread_bt_rx_cpu_percent")
        thread_bt_tx_cpu = numbers(success, "thread_bt_tx_cpu_percent")
        thread_idle_cpu = numbers(success, "thread_idle_cpu_percent")
        thread_other_cpu = numbers(success, "thread_other_cpu_percent")
        summary_cpu = cpu if cpu else client_cpu
        keygen_cpu = numbers(success, "keygen_cpu_ms")
        make_cert_cpu = numbers(success, "make_cert_cpu_ms")
        sign_cert_cpu = numbers(success, "sign_cert_cpu_ms")
        parse_cert_cpu = numbers(success, "parse_cert_cpu_ms")
        key_export_cpu = numbers(success, "key_export_cpu_ms")
        phase_cpu_total = numbers(success, "phase_cpu_total_ms")
        phase_wall = {
            phase: numbers(success, f"{phase}_wall_ms")
            for phase in PHASES
        }
        phase_thread_cpu = {
            (phase, bucket): numbers(
                success, f"{phase}_thread_{bucket}_cpu_percent"
            )
            for phase in PHASES
            for bucket in PHASE_THREAD_BUCKETS
        }
        phase_heap_peak = {
            phase: numbers(success, f"{phase}_heap_peak_bytes")
            for phase in PHASES
        }
        phase_counters = {
            (phase, counter, suffix): numbers(success, f"{phase}_{counter}_{suffix}")
            for phase in PHASES
            for counter, suffix in PHASE_DWT_METRICS
        }
        phase_counter_totals = {
            (counter, suffix): numbers(success, f"phase_{counter}_total_{suffix}")
            for counter, suffix in PHASE_DWT_METRICS
        }
        phase_dwt_samples = numbers(success, "phase_dwt_samples")
        phase_verify_values = [
            str(item.get("phase_cpu_verify", ""))
            for item in success
            if item.get("phase_cpu_verify", "") != ""
        ]
        phase_verify = ""
        if phase_verify_values:
            phase_verify = (
                "pass"
                if all(value == "pass" for value in phase_verify_values)
                else "fail"
            )
        dwt_supported_values = [
            str(item.get("dwt_counters_supported", ""))
            for item in success
            if item.get("dwt_counters_supported", "") != ""
        ]
        dwt_wrap_values = [
            str(item.get("dwt_wrap_risk", ""))
            for item in success
            if item.get("dwt_wrap_risk", "") != ""
        ]
        client_heap_peak = numbers(success, "client_heap_peak_bytes")
        firmware_ram = numbers(success, "firmware_static_ram_used_bytes")
        firmware_ram_percent = numbers(success, "firmware_static_ram_usage_percent")
        if not firmware_ram_percent:
            firmware_ram_percent = [
                float(value) for value in (
                    usage_percent(
                        item,
                        "firmware_static_ram_used_bytes",
                        "firmware_ram_capacity_bytes",
                    )
                    for item in success
                )
                if value != ""
            ]
        thread_stack_peak = numbers(success, "thread_stack_peak_percent")
        summary = {
            "component": base["component"],
            "owner": base["owner"],
            "cert_sig_alg": base["cert_sig_alg"],
            "sig_family": base.get("sig_family", ""),
            "sig_nist_level": base.get("sig_nist_level", ""),
            "builder": base["builder"],
            "generation_scope": base["generation_scope"],
            "status": status,
            "success_count": len(success),
            "fail_count": len(failed),
            "mean_wall_ms": f"{sum(wall) / len(wall):.3f}" if wall else "",
            "min_wall_ms": f"{min(wall):.3f}" if wall else "",
            "max_wall_ms": f"{max(wall):.3f}" if wall else "",
            "mean_cpu_ms": (
                f"{sum(summary_cpu) / len(summary_cpu):.3f}" if summary_cpu else ""
            ),
            "mean_user_cpu_ms": (
                f"{sum(user_cpu) / len(user_cpu):.3f}" if user_cpu else ""
            ),
            "mean_sys_cpu_ms": (
                f"{sum(sys_cpu) / len(sys_cpu):.3f}" if sys_cpu else ""
            ),
            "max_rss_kb": f"{max(rss):.0f}" if rss else "",
            **{
                f"mean_{metric}": (
                    f"{sum(values) / len(values):.3f}" if values else ""
                )
                for metric, values in server_resources.items()
            },
            **{
                f"mean_server_{phase}_{metric}": (
                    f"{sum(values) / len(values):.3f}" if values else ""
                )
                for (phase, metric), values in server_phase_values.items()
            },
            **{
                f"max_server_{phase}_rss_kb": (
                    f"{max(values):.0f}" if values else ""
                )
                for phase, values in server_phase_rss.items()
            },
            **{
                f"mean_server_{phase}_{metric}": (
                    f"{sum(values) / len(values):.3f}" if values else ""
                )
                for (phase, metric), values in server_phase_resources.items()
            },
            "mean_output_total_bytes": (
                f"{sum(output_bytes) / len(output_bytes):.0f}"
                if output_bytes else ""
            ),
            "server_chain_crt_bytes": (
                success[0].get("server_chain_crt_bytes", "") if success else ""
            ),
            "server_key_bytes": success[0].get("server_key_bytes", "") if success else "",
            "client_cert_crt_bytes": (
                success[0].get("client_cert_crt_bytes", "") if success else ""
            ),
            "client_key_bytes": success[0].get("client_key_bytes", "") if success else "",
            "client_csr_der_bytes": (
                success[0].get("client_csr_der_bytes", "") if success else ""
            ),
            "client_csr_pem_bytes": (
                success[0].get("client_csr_pem_bytes", "") if success else ""
            ),
            "mean_client_cpu_ms": (
                f"{sum(client_cpu) / len(client_cpu):.3f}" if client_cpu else ""
            ),
            "mean_thread_main_cpu_percent": (
                f"{sum(thread_main_cpu) / len(thread_main_cpu):.3f}"
                if thread_main_cpu else ""
            ),
            "mean_thread_sysworkq_cpu_percent": (
                f"{sum(thread_sysworkq_cpu) / len(thread_sysworkq_cpu):.3f}"
                if thread_sysworkq_cpu else ""
            ),
            "mean_thread_bt_rx_cpu_percent": (
                f"{sum(thread_bt_rx_cpu) / len(thread_bt_rx_cpu):.3f}"
                if thread_bt_rx_cpu else ""
            ),
            "mean_thread_bt_tx_cpu_percent": (
                f"{sum(thread_bt_tx_cpu) / len(thread_bt_tx_cpu):.3f}"
                if thread_bt_tx_cpu else ""
            ),
            "mean_thread_idle_cpu_percent": (
                f"{sum(thread_idle_cpu) / len(thread_idle_cpu):.3f}"
                if thread_idle_cpu else ""
            ),
            "mean_thread_other_cpu_percent": (
                f"{sum(thread_other_cpu) / len(thread_other_cpu):.3f}"
                if thread_other_cpu else ""
            ),
            "mean_keygen_cpu_ms": (
                f"{sum(keygen_cpu) / len(keygen_cpu):.3f}" if keygen_cpu else ""
            ),
            "mean_make_cert_cpu_ms": (
                f"{sum(make_cert_cpu) / len(make_cert_cpu):.3f}"
                if make_cert_cpu else ""
            ),
            "mean_sign_cert_cpu_ms": (
                f"{sum(sign_cert_cpu) / len(sign_cert_cpu):.3f}"
                if sign_cert_cpu else ""
            ),
            "mean_parse_cert_cpu_ms": (
                f"{sum(parse_cert_cpu) / len(parse_cert_cpu):.3f}"
                if parse_cert_cpu else ""
            ),
            "mean_key_export_cpu_ms": (
                f"{sum(key_export_cpu) / len(key_export_cpu):.3f}"
                if key_export_cpu else ""
            ),
            "mean_phase_cpu_total_ms": (
                f"{sum(phase_cpu_total) / len(phase_cpu_total):.3f}"
                if phase_cpu_total else ""
            ),
            "phase_cpu_verify": phase_verify,
            **{
                f"mean_phase_{counter}_total_{suffix}": (
                    f"{sum(values) / len(values):.3f}" if values else ""
                )
                for (counter, suffix), values in phase_counter_totals.items()
            },
            "max_phase_dwt_samples": (
                f"{max(phase_dwt_samples):.0f}" if phase_dwt_samples else ""
            ),
            "dwt_counters_supported": (
                "1" if any(value == "1" for value in dwt_supported_values)
                else "0" if dwt_supported_values else ""
            ),
            "dwt_wrap_risk": (
                "1" if any(value == "1" for value in dwt_wrap_values)
                else "0" if dwt_wrap_values else ""
            ),
            "max_client_heap_peak_bytes": (
                f"{max(client_heap_peak):.0f}" if client_heap_peak else ""
            ),
            "firmware_static_ram_used_bytes": (
                f"{max(firmware_ram):.0f}" if firmware_ram else ""
            ),
            "firmware_ram_capacity_bytes": (
                success[0].get("firmware_ram_capacity_bytes", "") if success else ""
            ),
            "firmware_static_ram_usage_percent": (
                f"{max(firmware_ram_percent):.2f}" if firmware_ram_percent else ""
            ),
            "max_thread_stack_peak_percent": (
                f"{max(thread_stack_peak):.2f}" if thread_stack_peak else ""
            ),
            "client_cert_der_bytes": (
                success[0].get("client_cert_der_bytes", "") if success else ""
            ),
            "client_key_der_bytes": (
                success[0].get("client_key_der_bytes", "") if success else ""
            ),
        }
        for phase in PHASES:
            wall_values = phase_wall[phase]
            heap_values = phase_heap_peak[phase]
            summary[f"mean_{phase}_wall_ms"] = (
                f"{sum(wall_values) / len(wall_values):.3f}"
                if wall_values else ""
            )
            summary[f"max_{phase}_heap_peak_bytes"] = (
                f"{max(heap_values):.0f}" if heap_values else ""
            )
            for counter, suffix in PHASE_DWT_METRICS:
                values = phase_counters[(phase, counter, suffix)]
                summary[f"mean_{phase}_{counter}_{suffix}"] = (
                    f"{sum(values) / len(values):.3f}" if values else ""
                )
            for bucket in PHASE_THREAD_BUCKETS:
                values = phase_thread_cpu[(phase, bucket)]
                summary[f"mean_{phase}_thread_{bucket}_cpu_percent"] = (
                    f"{sum(values) / len(values):.3f}" if values else ""
                )
        summaries.append(summary)
    return summaries


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    config_args, _ = config_parser.parse_known_args(argv)
    config = load_config(config_args.config)

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=config_args.config)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=1)
    parser.add_argument("--run-id")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--only-signature", action="append", default=[])
    parser.add_argument(
        "--server-builder",
        choices=("auto", "both", "openssl", "wolfssl"),
        default="auto",
        help=(
            "server certificate-chain generator. auto/both collects OpenSSL "
            "where available plus wolfSSL for comparison."
        ),
    )
    parser.add_argument(
        "--no-client-identity",
        action="store_true",
        help="deprecated; host-side client identity benchmark is skipped by default",
    )
    parser.add_argument(
        "--host-client-identity",
        action="store_true",
        help="also run the legacy host-side ECDSA-P-256 client CSR baseline",
    )
    parser.add_argument(
        "--no-board-client",
        action="store_true",
        help="skip the board-side wolfSSL client certificate benchmark",
    )
    parser.add_argument("--skip-client-build", action="store_true")
    parser.add_argument("--skip-client-flash", action="store_true")
    parser.add_argument("--serial-device", default=config["serial-device"])
    parser.add_argument("--serial-baud", type=int, default=115200)
    parser.add_argument("--serial-timeout-sec", type=float, default=30.0)
    parser.add_argument("--pi-host", default=config["pi-host"])
    parser.add_argument(
        "--pi-workdir",
        default="",
        help="remote workspace; defaults to /home/<SSH user>/peripheral-benchmark",
    )
    parser.add_argument("--ssh-key", default=config["ssh-key"])
    parser.add_argument("--nrfutil", default=default_nrfutil())
    parser.add_argument("--ncs-version", default=DEFAULT_NCS_VERSION)
    parser.add_argument("--ncs-chdir", default=default_ncs_chdir())
    parser.add_argument("--board", default="nrf52840dk/nrf52840")
    args = parser.parse_args(argv)
    args.ssh_key = os.path.expandvars(os.path.expanduser(args.ssh_key))
    args.pi_workdir = resolve_pi_workdir(args.pi_host, args.pi_workdir)
    return args


def board_args_from(args: argparse.Namespace) -> argparse.Namespace:
    return argparse.Namespace(
        config=args.config,
        run_id=args.run_id,
        skip_build=args.skip_client_build,
        skip_flash=args.skip_client_flash,
        serial_device=resolve_serial_device(args.serial_device),
        serial_baud=args.serial_baud,
        serial_timeout_sec=args.serial_timeout_sec,
        nrfutil=args.nrfutil,
        ncs_version=args.ncs_version,
        ncs_chdir=args.ncs_chdir,
        board=args.board,
    )


def board_client_error_row(
    signature: Signature,
    *,
    status: str,
    message: str,
) -> dict[str, object]:
    return {
        "attempt_index": 1,
        "component": "client_certificate",
        "owner": "client",
        "cert_sig_alg": signature.name,
        "sig_family": signature.family,
        "sig_nist_level": signature.nist_level,
        "builder": "wolfssl_board",
        "generation_scope": "client_self_signed_cert",
        "status": status,
        "message": message,
    }


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.iterations < 1:
        raise ValueError("--iterations must be at least 1")
    if args.limit is not None and args.limit < 1:
        raise ValueError("--limit must be at least 1")

    run_id = args.run_id or f"cert_chains_{datetime.now():%Y%m%d_%H%M%S}"
    run_dir = RESULTS / run_id
    if run_dir.exists():
        raise FileExistsError(f"refusing to overwrite {run_dir}")
    run_dir.mkdir(parents=True)
    log = run_dir / "certificate-benchmark.log"

    cases = signature_cases(read_cases(args.cases))
    if args.only_signature:
        wanted = set(args.only_signature)
        cases = [case for case in cases if case["cert_sig_alg"] in wanted]
        missing = wanted - {case["cert_sig_alg"] for case in cases}
        if missing:
            raise ValueError(f"unknown or disabled signatures: {', '.join(sorted(missing))}")
    if args.limit is not None:
        cases = cases[:args.limit]
    if not cases:
        raise ValueError("no signatures selected")

    attempts: list[dict[str, object]] = []
    if args.host_client_identity:
        ensure_image(ROOT / "docker" / "Dockerfile.pqc", log)
        client_case = {
            "case_id": "client_identity",
            "cert_sig_alg": "ECDSA-P-256",
        }
        signature = SIGNATURES_BY_NAME["ECDSA-P-256"]
        for attempt in range(1, args.iterations + 1):
            output = run_dir / "attempts" / "client_identity" / f"{attempt:03d}"
            rc, metrics, stdout = run_measured_container(
                output, client_identity_script(), log,
                setup_script=wolfssl_client_identity_setup_script(),
            )
            attempts.append(attempt_row(
                attempt_index=attempt,
                component="client_identity",
                owner="client",
                case=client_case,
                signature=signature,
                builder="wolfssl",
                generation_scope="client_key_and_certificate_request",
                output=output,
                status="success" if rc == 0 else "fail",
                metrics=metrics,
                message="" if rc == 0 else stdout.splitlines()[-1] if stdout else "",
            ))
            write_csv(run_dir / "attempts.csv", ATTEMPT_FIELDS, attempts)

    if not args.no_board_client:
        for case in cases:
            signature = SIGNATURES_BY_NAME[case["cert_sig_alg"]]
            for attempt in range(1, args.iterations + 1):
                print(
                    f"[client-cert] board wolfSSL {signature.name} "
                    f"attempt={attempt}/{args.iterations}",
                    flush=True,
                )
                board_args = board_args_from(args)
                if attempt > 1:
                    board_args.skip_build = True
                try:
                    board_row = run_board_client_certificate_benchmark(
                        board_args,
                        run_id=run_id,
                        run_dir=run_dir,
                        signature=signature.name,
                    )
                except subprocess.CalledProcessError as error:
                    board_row = board_client_error_row(
                        signature,
                        status="unsupported",
                        message=f"board build command failed: {error.returncode}",
                    )
                except Exception as error:
                    board_row = board_client_error_row(
                        signature,
                        status="fail",
                        message=str(error),
                    )
                board_row["attempt_index"] = attempt
                board_row["sig_family"] = signature.family
                board_row["sig_nist_level"] = signature.nist_level
                board_row["cpu_ms"] = board_row.get("client_cpu_ms", "")
                attempts.append(board_row)
                write_csv(run_dir / "attempts.csv", ATTEMPT_FIELDS, attempts)

    server_builders = {
        builder
        for case in cases
        for builder in server_builders_for(
            SIGNATURES_BY_NAME[case["cert_sig_alg"]], args.server_builder
        )
    }
    pi_runner = PiCertificateRunner(
        args.pi_host, args.pi_workdir, args.ssh_key, run_id
    )
    print(
        f"[setup] Preparing Raspberry Pi certificate generator on {args.pi_host}; "
        f"log={log}",
        flush=True,
    )
    pi_runner.start(log)
    try:
        pi_runner.prepare(log, server_builders)
        for case in cases:
            signature = SIGNATURES_BY_NAME[case["cert_sig_alg"]]
            builders = server_builders_for(signature, args.server_builder)
            for builder in builders:
                generation_scope = server_generation_scope(builder)
                remote_root = ""
                if builder == "openssl":
                    remote_root = pi_runner.ensure_server_root(
                        signature,
                        run_dir / "trust-anchors" / slug(signature.issuer_key_type),
                        log,
                    )
                for attempt in range(1, args.iterations + 1):
                    output = (
                        run_dir / "attempts" / slug(signature.name) /
                        slug(builder) / f"{attempt:03d}"
                    )
                    remote_output = pi_runner.remote_attempt_dir(
                        signature, builder, attempt
                    )
                    script = server_script_for(
                        signature,
                        builder,
                        output_dir=remote_output,
                        client_dir=remote_root,
                    )
                    print(
                        f"[cert-chain] Raspberry Pi {builder} {signature.name} "
                        f"attempt={attempt}/{args.iterations}",
                        flush=True,
                    )
                    rc, metrics, stdout = pi_runner.run_measured(
                        output, remote_output, script, log
                    )
                    attempts.append(attempt_row(
                        attempt_index=attempt,
                        component="server_chain",
                        owner="server",
                        case=case,
                        signature=signature,
                        builder=builder,
                        generation_scope=generation_scope,
                        output=output,
                        status="success" if rc == 0 else "fail",
                        metrics=metrics,
                        message=(
                            "" if rc == 0 else
                            stdout.splitlines()[-1] if stdout else ""
                        ),
                    ))
                    write_csv(run_dir / "attempts.csv", ATTEMPT_FIELDS, attempts)
    finally:
        pi_runner.stop()

    write_csv(run_dir / "summary.csv", SUMMARY_FIELDS, summarize(attempts))
    shutil.copy2(args.cases, run_dir / "input_cases.csv")
    print(f"results={run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
