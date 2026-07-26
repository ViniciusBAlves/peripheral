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
    generate_client_identity,
)
from benchmarklib.server_backends import HASH_BASED_SIGNATURES
from generate_cases import FIELDS as INPUT_FIELDS
from run_benchmarks import (
    DEFAULT_CONFIG,
    DEFAULT_NCS_VERSION,
    default_ncs_chdir,
    default_nrfutil,
    load_config,
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
    "keygen_lsu_cycles", "make_cert_lsu_cycles", "sign_cert_lsu_cycles",
    "parse_cert_lsu_cycles", "key_export_lsu_cycles",
    "phase_lsu_total_cycles", "keygen_cpi_cycles",
    "make_cert_cpi_cycles", "sign_cert_cpi_cycles", "parse_cert_cpi_cycles",
    "key_export_cpi_cycles", "phase_cpi_total_cycles",
    "phase_dwt_samples", "dwt_counters_supported", "dwt_wrap_risk",
    "client_heap_current_bytes", "client_heap_peak_bytes",
    "client_heap_free_bytes", "client_heap_capacity_bytes",
    "thread_stack_used_bytes", "thread_stack_capacity_bytes",
    "thread_stack_peak_percent", "client_cert_der_bytes",
    "client_key_der_bytes", "client_cert_der_capacity_bytes",
    "client_key_der_capacity_bytes", "client_hbs_state_capacity_bytes",
    "error_code", "message",
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
           "sys_cpu_us=%lld cpu_us=%lld max_rss_kb=%ld\n",
           exit_code, elapsed_us(start, end), timeval_us(usage.ru_utime),
           timeval_us(usage.ru_stime),
           timeval_us(usage.ru_utime) + timeval_us(usage.ru_stime),
           usage.ru_maxrss);
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
    for line in output.splitlines():
        if not line.startswith("[CERT_BENCH]"):
            continue
        values: dict[str, str] = {}
        for token in line.removeprefix("[CERT_BENCH]").strip().split():
            if "=" in token:
                key, value = token.split("=", 1)
                values[key] = value
        return values
    return {}


def ms(values: dict[str, str], key: str) -> str:
    try:
        return f"{float(values[key]) / 1000.0:.3f}"
    except (KeyError, ValueError):
        return ""


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
    match = re.fullmatch(r"RSA-PSS-(\d+)", key_type)
    if match:
        return f"-newkey rsa:{match.group(1)}"
    if key_type.startswith("ec:"):
        return f"-newkey ec -pkeyopt ec_paramgen_curve:{key_type.split(':', 1)[1]}"
    return f"-newkey {key_type}"


def hash_arg(key_type: str) -> str:
    match = re.fullmatch(r"RSA-PSS-(\d+)", key_type)
    if not match:
        return ""
    bits = int(match.group(1))
    return "-sha256" if bits <= 3072 else "-sha384" if bits <= 7680 else "-sha512"


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


def openssl_server_chain_script(signature: Signature) -> str:
    issuer_args = key_args(signature.issuer_key_type)
    leaf_args = key_args(signature.leaf_key_type)
    issuer_hash = hash_arg(signature.issuer_key_type)
    leaf_hash = hash_arg(signature.leaf_key_type)
    return f"""
cp /client/server_root.crt /client/server_root.key /out/
printf 'basicConstraints=critical,CA:TRUE\\nkeyUsage=critical,keyCertSign,cRLSign\\nsubjectKeyIdentifier=hash\\nauthorityKeyIdentifier=keyid,issuer\\n' \\
  > /out/intermediate.ext
printf 'basicConstraints=critical,CA:FALSE\\nkeyUsage=critical,digitalSignature,keyEncipherment\\nextendedKeyUsage=critical,serverAuth\\nsubjectAltName=DNS:localhost,IP:127.0.0.1\\nsubjectKeyIdentifier=hash\\nauthorityKeyIdentifier=keyid,issuer\\n' \\
  > /out/server.ext
openssl req -new {issuer_args} -keyout /out/server_intermediate.key \\
  -out /out/server_intermediate.csr -nodes -subj /CN={signature.name}_Intermediate \\
  {issuer_hash}
openssl x509 -req -in /out/server_intermediate.csr -CA /out/server_root.crt \\
  -CAkey /out/server_root.key -CAcreateserial -out /out/server_intermediate.crt \\
  -not_before {CERT_NOT_BEFORE} -not_after {CERT_NOT_AFTER} \\
  -extfile /out/intermediate.ext
openssl req -new {leaf_args} -keyout /out/server.key -out /out/server.csr \\
  -nodes -subj /CN=localhost {leaf_hash}
openssl x509 -req -in /out/server.csr -CA /out/server_intermediate.crt \\
  -CAkey /out/server_intermediate.key -CAcreateserial -out /out/server.crt \\
  -not_before {CERT_NOT_BEFORE} -not_after {CERT_NOT_AFTER} \\
  -extfile /out/server.ext {issuer_hash}
cat /out/server.crt /out/server_intermediate.crt > /out/server_chain.crt
openssl verify -purpose sslserver -CAfile /out/server_root.crt \\
  -untrusted /out/server_intermediate.crt /out/server.crt
"""


def hbs_server_chain_script(signature: Signature) -> str:
    return f"hbs_certgen {shlex.quote(signature.name)} /out"


def wolfssl_server_chain_script(signature: Signature) -> str:
    return f"wolfssl_certgen {shlex.quote(signature.name)} /out"


def server_builder_for(signature: Signature, requested: str) -> str:
    if requested == "auto":
        return "wolfssl-hbs" if signature.name in HASH_BASED_SIGNATURES else "openssl"
    if requested == "wolfssl" and signature.name in HASH_BASED_SIGNATURES:
        return "wolfssl-hbs"
    return requested


def server_generation_scope(builder: str) -> str:
    if builder == "wolfssl-hbs":
        return "hash_based_root_and_leaf"
    if builder == "wolfssl":
        return "wolfssl_root_and_leaf"
    return "leaf_and_intermediate_under_existing_root"


def server_script_for(signature: Signature, builder: str) -> str:
    if builder == "wolfssl-hbs":
        return hbs_server_chain_script(signature)
    if builder == "wolfssl":
        return wolfssl_server_chain_script(signature)
    return openssl_server_chain_script(signature)


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
    groups: dict[tuple[str, str], list[dict[str, object]]] = {}
    for row in rows:
        groups.setdefault((str(row["component"]), str(row["cert_sig_alg"])), []).append(row)

    def numbers(items: list[dict[str, object]], field: str) -> list[float]:
        values = []
        for item in items:
            value = item.get(field, "")
            if value != "":
                values.append(float(value))
        return values

    summaries = []
    for (_component, _signature), items in sorted(groups.items()):
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
        phase_lsu = {
            phase: numbers(success, f"{phase}_lsu_cycles")
            for phase in PHASES
        }
        phase_cpi = {
            phase: numbers(success, f"{phase}_cpi_cycles")
            for phase in PHASES
        }
        phase_lsu_total = numbers(success, "phase_lsu_total_cycles")
        phase_cpi_total = numbers(success, "phase_cpi_total_cycles")
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
            "mean_phase_lsu_total_cycles": (
                f"{sum(phase_lsu_total) / len(phase_lsu_total):.3f}"
                if phase_lsu_total else ""
            ),
            "mean_phase_cpi_total_cycles": (
                f"{sum(phase_cpi_total) / len(phase_cpi_total):.3f}"
                if phase_cpi_total else ""
            ),
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
            lsu_values = phase_lsu[phase]
            cpi_values = phase_cpi[phase]
            summary[f"mean_{phase}_lsu_cycles"] = (
                f"{sum(lsu_values) / len(lsu_values):.3f}"
                if lsu_values else ""
            )
            summary[f"mean_{phase}_cpi_cycles"] = (
                f"{sum(cpi_values) / len(cpi_values):.3f}"
                if cpi_values else ""
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
        choices=("auto", "openssl", "wolfssl"),
        default="auto",
        help=(
            "server certificate-chain generator. auto keeps the existing "
            "OpenSSL path except LMS/XMSS, which use wolfSSL."
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
    parser.add_argument("--nrfutil", default=default_nrfutil())
    parser.add_argument("--ncs-version", default=DEFAULT_NCS_VERSION)
    parser.add_argument("--ncs-chdir", default=default_ncs_chdir())
    parser.add_argument("--board", default="nrf52840dk/nrf52840")
    return parser.parse_args(argv)


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

    ensure_image(ROOT / "docker" / "Dockerfile.pqc", log)
    client_dir = run_dir / "trust-anchors"
    generate_client_identity(client_dir, log)

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

    for case in cases:
        signature = SIGNATURES_BY_NAME[case["cert_sig_alg"]]
        builder = server_builder_for(signature, args.server_builder)
        generation_scope = server_generation_scope(builder)
        script = server_script_for(signature, builder)
        mounts = [] if builder != "openssl" else [(client_dir, "/client", True)]
        for attempt in range(1, args.iterations + 1):
            output = (
                run_dir / "attempts" / slug(signature.name) / f"{attempt:03d}"
            )
            print(
                f"[cert-chain] {signature.name} attempt={attempt}/{args.iterations}",
                flush=True,
            )
            rc, metrics, stdout = run_measured_container(
                output, script, log, mounts=mounts
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
                message="" if rc == 0 else stdout.splitlines()[-1] if stdout else "",
            ))
            write_csv(run_dir / "attempts.csv", ATTEMPT_FIELDS, attempts)

    write_csv(run_dir / "summary.csv", SUMMARY_FIELDS, summarize(attempts))
    shutil.copy2(args.cases, run_dir / "input_cases.csv")
    print(f"results={run_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
