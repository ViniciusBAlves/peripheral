#!/usr/bin/env python3
"""Benchmark certificate-chain generation and validation independently of TLS."""

from __future__ import annotations

import argparse
import csv
import json
import os
import random
import re
import shlex
import shutil
import statistics
import subprocess
import time
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
from benchmarklib.firmware import build as build_firmware
from benchmarklib.firmware import flash as flash_firmware
from benchmarklib.firmware import reset as reset_firmware
from generate_cases import FIELDS as INPUT_FIELDS


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
WORK = ROOT / "work"
WOLFSSL_COMPAT_CFLAGS = (
    "-DFP_MAX_BITS=32768 -DRSA_MAX_SIZE=16384 -DWC_MAX_RSA_BITS=16384"
)
MAX_ALGORITHM_TIMEOUT_SEC = 15 * 60

ATTEMPT_FIELDS = [
    "attempt_index", "component", "owner", "cert_sig_alg", "sig_family",
    "sig_nist_level", "sig_public_key_bytes", "sig_private_key_bytes",
    "sig_signature_bytes", "builder", "generation_scope", "status",
    "wall_ms", "cpu_ms", "user_cpu_ms", "sys_cpu_ms", "max_rss_kb",
    "server_root_der_bytes", "server_root_crt_bytes",
    "server_intermediate_crt_bytes", "server_leaf_crt_bytes",
    "server_chain_crt_bytes", "server_key_bytes",
    "client_ca_crt_bytes", "client_cert_crt_bytes", "client_key_bytes",
    "client_csr_der_bytes", "client_csr_pem_bytes", "output_total_bytes",
    "certificate_keygen_ms", "certificate_make_body_ms",
    "certificate_sign_ms", "certificate_verify_ms", "certificate_total_ms",
    "certificate_der_bytes", "client_cpu_cycles", "client_cycle_hz",
    "client_heap_current_bytes", "client_heap_peak_bytes",
    "client_heap_free_bytes", "client_heap_capacity_bytes",
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
    "mean_certificate_keygen_ms", "mean_certificate_make_body_ms",
    "mean_certificate_sign_ms", "mean_certificate_verify_ms",
    "median_certificate_sign_ms", "p95_certificate_sign_ms",
    "stddev_certificate_sign_ms", "mean_certificate_total_ms",
    "mean_certificate_der_bytes",
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
    XSTRNCPY(cert->subject.commonName, "nrf5340-benchmark", CTC_NAME_SIZE);
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

    def percentile(values: list[float], percent: float) -> float:
        ordered = sorted(values)
        position = (len(ordered) - 1) * percent
        lower = int(position)
        upper = min(lower + 1, len(ordered) - 1)
        fraction = position - lower
        return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction

    summaries = []
    for (_component, _signature), items in sorted(groups.items()):
        success = [item for item in items if item["status"] == "success"]
        base = items[0]
        wall = numbers(success, "wall_ms")
        cpu = numbers(success, "cpu_ms")
        user_cpu = numbers(success, "user_cpu_ms")
        sys_cpu = numbers(success, "sys_cpu_ms")
        rss = numbers(success, "max_rss_kb")
        output_bytes = numbers(success, "output_total_bytes")
        keygen = numbers(success, "certificate_keygen_ms")
        make_body = numbers(success, "certificate_make_body_ms")
        sign = numbers(success, "certificate_sign_ms")
        verify = numbers(success, "certificate_verify_ms")
        cert_total = numbers(success, "certificate_total_ms")
        cert_der = numbers(success, "certificate_der_bytes")
        summaries.append({
            "component": base["component"],
            "owner": base["owner"],
            "cert_sig_alg": base["cert_sig_alg"],
            "sig_family": base["sig_family"],
            "sig_nist_level": base["sig_nist_level"],
            "builder": base["builder"],
            "generation_scope": base["generation_scope"],
            "status": "success" if len(success) == len(items) else "fail",
            "success_count": len(success),
            "fail_count": len(items) - len(success),
            "mean_wall_ms": f"{sum(wall) / len(wall):.3f}" if wall else "",
            "min_wall_ms": f"{min(wall):.3f}" if wall else "",
            "max_wall_ms": f"{max(wall):.3f}" if wall else "",
            "mean_cpu_ms": f"{sum(cpu) / len(cpu):.3f}" if cpu else "",
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
            "server_key_bytes": (
                success[0].get("server_key_bytes", "") if success else ""
            ),
            "client_cert_crt_bytes": (
                success[0].get("client_cert_crt_bytes", "") if success else ""
            ),
            "client_key_bytes": (
                success[0].get("client_key_bytes", "") if success else ""
            ),
            "client_csr_der_bytes": (
                success[0].get("client_csr_der_bytes", "") if success else ""
            ),
            "client_csr_pem_bytes": (
                success[0].get("client_csr_pem_bytes", "") if success else ""
            ),
            "mean_certificate_keygen_ms": (
                f"{sum(keygen) / len(keygen):.3f}" if keygen else ""
            ),
            "mean_certificate_make_body_ms": (
                f"{sum(make_body) / len(make_body):.3f}" if make_body else ""
            ),
            "mean_certificate_sign_ms": (
                f"{sum(sign) / len(sign):.3f}" if sign else ""
            ),
            "median_certificate_sign_ms": (
                f"{statistics.median(sign):.3f}" if sign else ""
            ),
            "p95_certificate_sign_ms": (
                f"{percentile(sign, 0.95):.3f}" if sign else ""
            ),
            "stddev_certificate_sign_ms": (
                f"{statistics.stdev(sign):.3f}" if len(sign) > 1 else
                "0.000" if sign else ""
            ),
            "mean_certificate_verify_ms": (
                f"{sum(verify) / len(verify):.3f}" if verify else ""
            ),
            "mean_certificate_total_ms": (
                f"{sum(cert_total) / len(cert_total):.3f}" if cert_total else ""
            ),
            "mean_certificate_der_bytes": (
                f"{sum(cert_der) / len(cert_der):.0f}" if cert_der else ""
            ),
        })
    return summaries


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


def certificate_timeout(signature: str, default: float) -> float:
    del signature
    return min(default, MAX_ALGORITHM_TIMEOUT_SEC)


def us_to_ms(values: dict[str, str], key: str) -> str:
    try:
        return f"{int(values[key]) / 1000.0:.3f}"
    except (KeyError, ValueError):
        return ""


def on_device_attempt_row(
    attempt: int,
    case: dict[str, str],
    signature: Signature,
    values: dict[str, str],
) -> dict[str, object]:
    status = values.get("status", "fail").lower()
    reported_sizes = (
        int(values.get("sig_public_key_bytes", "0") or 0),
        int(values.get("sig_private_key_bytes", "0") or 0),
        int(values.get("sig_signature_bytes", "0") or 0),
    )
    expected_sizes = (
        signature.public_key_bytes,
        signature.private_key_bytes,
        signature.signature_bytes,
    )
    size_mismatch = status == "success" and reported_sizes != expected_sizes
    if size_mismatch:
        status = "fail"
    total_ms = us_to_ms(values, "certificate_total_us")
    cycle_hz = int(values.get("client_cycle_hz", "0") or 0)
    cycles = int(values.get("client_cpu_cycles", "0") or 0)
    cpu_ms = f"{cycles * 1000.0 / cycle_hz:.3f}" if cycle_hz else ""
    return {
        "attempt_index": attempt,
        "component": "on_device_certificate",
        "owner": "client",
        "cert_sig_alg": signature.name,
        "sig_family": signature.family,
        "sig_nist_level": signature.nist_level,
        "sig_public_key_bytes": values.get("sig_public_key_bytes", ""),
        "sig_private_key_bytes": values.get("sig_private_key_bytes", ""),
        "sig_signature_bytes": values.get("sig_signature_bytes", ""),
        "builder": "wolfssl-nrf5340",
        "generation_scope": "keypair_self_signed_x509_sign_and_verify",
        "status": status,
        "wall_ms": total_ms,
        "cpu_ms": cpu_ms,
        "max_rss_kb": "",
        "output_total_bytes": values.get("certificate_der_bytes", ""),
        "certificate_keygen_ms": us_to_ms(values, "certificate_keygen_us"),
        "certificate_make_body_ms": us_to_ms(
            values, "certificate_make_body_us"
        ),
        "certificate_sign_ms": us_to_ms(values, "certificate_sign_us"),
        "certificate_verify_ms": us_to_ms(values, "certificate_verify_us"),
        "certificate_total_ms": total_ms,
        "certificate_der_bytes": values.get("certificate_der_bytes", ""),
        "client_cpu_cycles": values.get("client_cpu_cycles", ""),
        "client_cycle_hz": values.get("client_cycle_hz", ""),
        "client_heap_current_bytes": values.get(
            "client_heap_current_bytes", ""
        ),
        "client_heap_peak_bytes": values.get("client_heap_peak_bytes", ""),
        "client_heap_free_bytes": values.get("client_heap_free_bytes", ""),
        "client_heap_capacity_bytes": values.get(
            "client_heap_capacity_bytes", ""
        ),
        "error_code": (
            "metadata_mismatch" if size_mismatch else values.get("error", "")
        ),
        "message": (
            f"reported_signature_sizes={reported_sizes},expected={expected_sizes}"
            if size_mismatch else
            "" if status == "success" else values.get("stage", "")
        ),
    }


def default_nrfutil() -> str:
    return shutil.which("nrfutil") or str(Path.home() / ".local/bin/nrfutil")


def default_ncs_chdir() -> str:
    candidates = (
        Path.home() / "Documents/ncs/v3.3.0/nrf",
        Path.home() / "ncs/v3.3.0/nrf",
    )
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return str(candidates[0])


def run_on_device(args: argparse.Namespace) -> int:
    cases = signature_cases(read_cases(args.cases))
    if args.only_signature:
        wanted = set(args.only_signature)
        cases = [case for case in cases if case["cert_sig_alg"] in wanted]
        missing = wanted - {case["cert_sig_alg"] for case in cases}
        if missing:
            raise ValueError(
                f"unknown or disabled signatures: {', '.join(sorted(missing))}"
            )
    random.Random(args.seed).shuffle(cases)
    if args.limit is not None:
        cases = cases[:args.limit]
    if not cases:
        raise ValueError("no signatures selected")

    run_id = args.run_id or f"cert_device_{datetime.now():%Y%m%d_%H%M%S}_{args.seed}"
    run_dir = RESULTS / run_id
    if run_dir.exists():
        raise FileExistsError(f"refusing to overwrite {run_dir}")
    run_dir.mkdir(parents=True)
    shutil.copy2(args.cases, run_dir / "input_cases.csv")
    (run_dir / "seed.txt").write_text(f"{args.seed}\n")
    (run_dir / "run_config.json").write_text(json.dumps({
        "mode": "on-device-certificate-generation",
        "board": args.board,
        "serial_device": args.serial_device,
        "iterations": args.iterations,
        "seed": args.seed,
        "attempt_timeout_sec": min(
            args.attempt_timeout_sec, MAX_ALGORITHM_TIMEOUT_SEC
        ),
    }, indent=2) + "\n")
    write_csv(
        run_dir / "run_manifest.csv",
        ["sequence", *INPUT_FIELDS, "seed", "run_id"],
        [
            {
                "sequence": sequence, **case, "seed": args.seed,
                "run_id": run_id,
            }
            for sequence, case in enumerate(cases, 1)
        ],
    )

    build_dir = WORK / "firmware-build" / "certificate-gen-nrf5340"
    if args.skip_build and not (build_dir / "zephyr/zephyr.hex").exists():
        raise FileNotFoundError(
            f"--skip-build requested but {build_dir / 'zephyr/zephyr.hex'} "
            "does not exist"
        )
    if not args.skip_build:
        print(f"[build] certificate firmware -> {build_dir}", flush=True)
        build_firmware(
            firmware_dir=ROOT / "firmware",
            build_dir=build_dir,
            generated_dir=run_dir,
            log=run_dir / "build.log",
            nrfutil=args.nrfutil,
            ncs_version=args.ncs_version,
            ncs_chdir=args.ncs_chdir,
            board=args.board,
            mlkem_backend="wolfssl",
            pqm4_dir=None,
            certificate_gen=True,
        )
    if not args.skip_flash:
        print("[flash] programming certificate firmware", flush=True)
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
            serial_port, board_log, "[BENCH_READY]", args.board_ready_timeout_sec
        )
        for sequence, case in enumerate(cases, 1):
            signature = SIGNATURES_BY_NAME[case["cert_sig_alg"]]
            for attempt in range(1, args.iterations + 1):
                print(
                    f"[{sequence}/{len(cases)}] {signature.name} "
                    f"attempt={attempt}/{args.iterations}",
                    flush=True,
                )
                command = (
                    f"CERTGEN certgen__{slug(signature.name)} "
                    f"{signature.name} {attempt}\n"
                )
                serial_port.write(command.encode())
                serial_port.flush()
                try:
                    timeout = certificate_timeout(
                        signature.name, args.attempt_timeout_sec
                    )
                    values = wait_for_board_marker(
                        serial_port, board_log, "[BENCH_CERT_RESULT]",
                        timeout,
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
                attempts.append(
                    on_device_attempt_row(attempt, case, signature, values)
                )
                if values.get("status") == "timeout":
                    remaining = args.iterations - attempt
                    print(
                        f"  timeout after {timeout:g}s; cancelling "
                        f"{remaining} remaining {signature.name} iteration(s)",
                        flush=True,
                    )
                    for cancelled in range(attempt + 1, args.iterations + 1):
                        attempts.append(on_device_attempt_row(
                            cancelled, case, signature, {
                                "status": "cancelled",
                                "stage": "cancelled_after_algorithm_timeout",
                                "error": "algorithm_timeout",
                            },
                        ))
                write_csv(
                    run_dir / "attempts.csv", ATTEMPT_FIELDS, attempts
                )
                if values.get("status") == "timeout":
                    break

    write_csv(run_dir / "summary.csv", SUMMARY_FIELDS, summarize(attempts))
    print(f"results={run_dir}")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    config_parser = argparse.ArgumentParser(add_help=False)
    config_parser.add_argument(
        "--config", type=Path, default=ROOT / "config.json"
    )
    config_args, _ = config_parser.parse_known_args(argv)
    config = json.loads(config_args.config.read_text())

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=config_args.config)
    parser.add_argument("--cases", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=1)
    parser.add_argument("--seed", type=int, default=123)
    parser.add_argument("--run-id")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--only-signature", action="append", default=[])
    parser.add_argument(
        "--host-only", action="store_true",
        help="run the legacy Docker/OpenSSL server-chain benchmark",
    )
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-flash", action="store_true")
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
    parser.add_argument(
        "--no-client-identity",
        action="store_true",
        help="skip the client identity provisioning benchmark",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.iterations < 1:
        raise ValueError("--iterations must be at least 1")
    if args.limit is not None and args.limit < 1:
        raise ValueError("--limit must be at least 1")
    if args.attempt_timeout_sec <= 0:
        raise ValueError("--attempt-timeout-sec must be positive")
    if not args.host_only:
        return run_on_device(args)

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
    if not args.no_client_identity:
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

    for case in cases:
        signature = SIGNATURES_BY_NAME[case["cert_sig_alg"]]
        hash_based = signature.name in HASH_BASED_SIGNATURES
        builder = "wolfssl-hbs" if hash_based else "openssl"
        generation_scope = (
            "hash_based_root_and_leaf"
            if hash_based else "leaf_and_intermediate_under_existing_root"
        )
        script = (
            hbs_server_chain_script(signature)
            if hash_based else openssl_server_chain_script(signature)
        )
        mounts = [] if hash_based else [(client_dir, "/client", True)]
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
