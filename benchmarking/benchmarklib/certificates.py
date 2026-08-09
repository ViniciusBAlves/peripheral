from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

from .algorithms import KEMS_BY_NAME, SIGNATURES_BY_NAME, Signature, slug
from .server_backends import HASH_BASED_SIGNATURES


IMAGE = "peripheral-pqc-openssl:3.10"
ROOT = Path(__file__).resolve().parents[1]
CERT_CACHE = ROOT / "work" / "certificate-cache" / "v9"
LEGACY_CERT_CACHES = (ROOT / "work" / "certificate-cache" / "v1",)
MIN_CACHE_VALID_SECONDS = 7 * 24 * 60 * 60
CERT_NOT_BEFORE = "20200101000000Z"
CERT_NOT_AFTER = "20360101000000Z"


def run(command: list[str], *, log: Path | None = None) -> None:
    if log:
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("a") as stream:
            stream.write(f"$ {' '.join(command)}\n")
            proc = subprocess.run(command, text=True, stdout=stream, stderr=subprocess.STDOUT)
    else:
        proc = subprocess.run(command)
    if proc.returncode:
        raise subprocess.CalledProcessError(proc.returncode, command)


def ensure_image(dockerfile: Path, log: Path) -> None:
    probe_command = [
        "docker", "run", "--rm", IMAGE, "sh", "-ec",
        "openssl version; "
        "openssl list -kem-algorithms | grep -Eq 'MLKEM512|ML-KEM-512'; "
        "openssl list -signature-algorithms | grep -q 'SLH-DSA-SHAKE-256s'; "
        "command -v hbs_certgen; "
        "command -v wolfssl_certgen",
    ]
    image = subprocess.run(
        ["docker", "image", "inspect", IMAGE],
        capture_output=True,
    )
    probe = None
    if image.returncode == 0:
        with log.open("a") as stream:
            stream.write(f"$ {' '.join(probe_command)}\n")
            probe = subprocess.run(
                probe_command,
                text=True,
                stdout=stream,
                stderr=subprocess.STDOUT,
            )

    if image.returncode != 0 or probe is None or probe.returncode != 0:
        with log.open("a") as stream:
            stream.write(
                "Docker image is missing or stale; rebuilding from "
                f"{dockerfile}.\n"
            )
        run(
            [
                "docker", "build", "-t", IMAGE, "-f", str(dockerfile),
                str(dockerfile.parent.parent),
            ],
            log=log,
        )

    run(probe_command, log=log)


def _rsa_bits(key_type: str) -> int | None:
    match = re.fullmatch(r"RSA-PSS-(\d+)", key_type)
    return int(match.group(1)) if match else None


def _key_args(key_type: str) -> str:
    ecdsa_curves = {
        "ECDSA-P-256": "prime256v1",
        "ECDSA-P-384": "secp384r1",
        "ECDSA-P-521": "secp521r1",
    }
    bits = _rsa_bits(key_type)
    if bits:
        return f"-newkey rsa:{bits}"
    if key_type in ecdsa_curves:
        return f"-newkey ec -pkeyopt ec_paramgen_curve:{ecdsa_curves[key_type]}"
    if key_type.startswith("ec:"):
        return f"-newkey ec -pkeyopt ec_paramgen_curve:{key_type.split(':', 1)[1]}"
    return f"-newkey {key_type}"


def _hash_arg(key_type: str) -> str:
    bits = _rsa_bits(key_type)
    if not bits:
        return ""
    return "-sha256" if bits <= 3072 else "-sha384" if bits <= 7680 else "-sha512"


def _client_signature_algorithms(name: str) -> str:
    ecdsa = {
        "ECDSA-P-256": "ECDSA+SHA256",
        "ECDSA-P-384": "ECDSA+SHA384",
        "ECDSA-P-521": "ECDSA+SHA512",
    }
    rsa_pss = {
        "RSA-PSS-3072": "rsa_pss_rsae_sha256",
        "RSA-PSS-7680": "rsa_pss_rsae_sha384",
        "RSA-PSS-15360": "rsa_pss_rsae_sha512",
    }
    return ecdsa.get(name) or rsa_pss.get(name) or name


def _docker_script(output: Path, script: str, log: Path) -> None:
    output.mkdir(parents=True, exist_ok=True)
    run(
        [
            "docker", "run", "--rm",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "-v", f"{output.resolve()}:/out",
            IMAGE, "sh", "-ec", script,
        ],
        log=log,
    )


def _append_log(log: Path, message: str) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a") as stream:
        stream.write(message.rstrip() + "\n")


def _copy_files(source: Path, destination: Path, names: tuple[str, ...]) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for name in names:
        shutil.copy2(source / name, destination / name)


def _cert_is_valid(path: Path, *, min_valid_seconds: int = MIN_CACHE_VALID_SECONDS) -> bool:
    if not path.exists():
        return False
    proc = subprocess.run(
        [
            "docker", "run", "--rm",
            "-v", f"{path.parent.resolve()}:/certs:ro",
            IMAGE, "openssl", "x509",
            "-checkend", str(min_valid_seconds),
            "-noout", "-in", f"/certs/{path.name}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return proc.returncode == 0


def _all_present(directory: Path, names: tuple[str, ...]) -> bool:
    return all((directory / name).exists() for name in names)


def generate_client_identity(
    output: Path,
    log: Path,
    certificate_verify_alg: str = "ECDSA-P-256",
) -> None:
    required = (
        "client_ca.crt", "client.crt", "client.key", "client_ca.der",
        "client_cert.der", "client_key.der", "server_root.crt",
        "server_root.key", "server_root.der",
    )
    certs = ("client_ca.crt", "client.crt", "server_root.crt")
    if _all_present(output, required) and all(_cert_is_valid(output / name) for name in certs):
        return
    cache = CERT_CACHE / "client-identity" / slug(certificate_verify_alg)
    if _all_present(cache, required) and all(_cert_is_valid(cache / name) for name in certs):
        _append_log(log, f"[cert-cache] Reusing client identity from {cache}")
        _copy_files(cache, output, required)
        return
    _append_log(log, f"[cert-cache] Generating client identity into {cache}")
    shutil.rmtree(cache, ignore_errors=True)
    cache.mkdir(parents=True, exist_ok=True)
    client_key_args = _key_args(certificate_verify_alg)
    client_hash_arg = _hash_arg(certificate_verify_alg)
    script = f"""
cat > /out/client.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,clientAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /out/client_ca.key -out /out/client_ca.crt -nodes \
  -subj /CN=Peripheral_Benchmark_Client_CA \
  -not_before {CERT_NOT_BEFORE} -not_after {CERT_NOT_AFTER} \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign
openssl req -new {client_key_args} \
  -keyout /out/client.key -out /out/client.csr -nodes \
  -subj /CN=nrf52840-benchmark {client_hash_arg}
openssl x509 -req -in /out/client.csr -CA /out/client_ca.crt \
  -CAkey /out/client_ca.key -CAcreateserial -out /out/client.crt \
  -not_before {CERT_NOT_BEFORE} -not_after {CERT_NOT_AFTER} \
  -extfile /out/client.ext
openssl x509 -in /out/client_ca.crt -outform DER -out /out/client_ca.der
openssl x509 -in /out/client.crt -outform DER -out /out/client_cert.der
openssl pkey -in /out/client.key -outform DER -out /out/client_key.der
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /out/server_root.key -out /out/server_root.crt -nodes \
  -subj /CN=Peripheral_Benchmark_Server_Root \
  -not_before {CERT_NOT_BEFORE} -not_after {CERT_NOT_AFTER} \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign
openssl x509 -in /out/server_root.crt -outform DER -out /out/server_root.der
openssl verify -purpose sslclient -CAfile /out/client_ca.crt /out/client.crt
"""
    _docker_script(cache, script, log)
    _copy_files(cache, output, required)


def generate_server_case(case: dict[str, str], output: Path, client_dir: Path, log: Path) -> None:
    signature: Signature = SIGNATURES_BY_NAME[case["cert_sig_alg"]]
    if signature.name in HASH_BASED_SIGNATURES:
        cached_required = (
            "server_root.crt", "server_root.der", "server.crt",
            "server.key", "server_chain.crt",
        )
        output_required = (
            *cached_required, "client_ca.crt", "client_ca.der",
            "openssl.cnf", "mosquitto.conf",
        )
        if (
            _all_present(output, output_required)
            and _cert_is_valid(output / "server_root.crt")
            and _cert_is_valid(output / "server.crt")
        ):
            shutil.copy2(client_dir / "client_ca.crt", output / "client_ca.crt")
            shutil.copy2(client_dir / "client_ca.der", output / "client_ca.der")
            write_case_configs(case, output)
            return
        cache = CERT_CACHE / "server" / slug(signature.name)
        legacy_caches = [
            legacy / "server" / slug(signature.name)
            for legacy in LEGACY_CERT_CACHES
        ]
        if not (
            _all_present(cache, cached_required)
            and _cert_is_valid(cache / "server_root.crt")
            and _cert_is_valid(cache / "server.crt")
        ):
            legacy_cache = next(
                (
                    item for item in legacy_caches
                    if _all_present(item, cached_required)
                    and _cert_is_valid(item / "server_root.crt")
                    and _cert_is_valid(item / "server.crt")
                ),
                None,
            )
            if legacy_cache is not None:
                _append_log(
                    log,
                    f"[cert-cache] Migrating {signature.name} server chain "
                    f"from {legacy_cache}",
                )
                shutil.rmtree(cache, ignore_errors=True)
                _copy_files(legacy_cache, cache, cached_required)
            else:
                _append_log(log, f"[cert-cache] Generating {signature.name} server chain into {cache}")
                shutil.rmtree(cache, ignore_errors=True)
                generate_hash_based_server_case(signature.name, cache, client_dir, log)
        else:
            _append_log(log, f"[cert-cache] Reusing {signature.name} server chain from {cache}")
        _copy_files(cache, output, cached_required)
        shutil.copy2(client_dir / "client_ca.crt", output / "client_ca.crt")
        shutil.copy2(client_dir / "client_ca.der", output / "client_ca.der")
        write_case_configs(case, output)
        return
    cached_required = (
        "server_root.crt", "server_root.key", "server_root.der",
        "server.crt", "server.key", "server_chain.crt",
    )
    output_required = (
        *cached_required, "client_ca.crt", "client_ca.der",
        "openssl.cnf", "mosquitto.conf",
    )
    if (
        _all_present(output, output_required)
        and _cert_is_valid(output / "server_root.crt")
        and _cert_is_valid(output / "server.crt")
    ):
        shutil.copy2(client_dir / "client_ca.crt", output / "client_ca.crt")
        shutil.copy2(client_dir / "client_ca.der", output / "client_ca.der")
        write_case_configs(case, output)
        return
    cache = CERT_CACHE / "server" / slug(signature.name)
    if (
        _all_present(cache, cached_required)
        and _cert_is_valid(cache / "server_root.crt")
        and _cert_is_valid(cache / "server.crt")
    ):
        _append_log(log, f"[cert-cache] Reusing {signature.name} server chain from {cache}")
        _copy_files(cache, output, cached_required)
        shutil.copy2(client_dir / "client_ca.crt", output / "client_ca.crt")
        shutil.copy2(client_dir / "client_ca.der", output / "client_ca.der")
        write_case_configs(case, output)
        return
    _append_log(log, f"[cert-cache] Generating {signature.name} server chain into {cache}")
    shutil.rmtree(cache, ignore_errors=True)
    cache.mkdir(parents=True, exist_ok=True)
    issuer_args = _key_args(signature.issuer_key_type)
    leaf_args = _key_args(signature.leaf_key_type)
    issuer_hash = _hash_arg(signature.issuer_key_type)
    leaf_hash = _hash_arg(signature.leaf_key_type)
    root_setup = f"""
openssl req -x509 -new {issuer_args} \
  -keyout /out/server_root.key -out /out/server_root.crt -nodes \
  -subj /CN=Peripheral_Benchmark_{signature.name}_Server_Root \
  -not_before {CERT_NOT_BEFORE} -not_after {CERT_NOT_AFTER} \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign
openssl x509 -in /out/server_root.crt -outform DER -out /out/server_root.der
"""
    script = f"""
{root_setup}
printf 'basicConstraints=critical,CA:FALSE\\nkeyUsage=critical,digitalSignature,keyEncipherment\\nextendedKeyUsage=critical,serverAuth\\nsubjectAltName=DNS:localhost,IP:127.0.0.1\\nsubjectKeyIdentifier=hash\\nauthorityKeyIdentifier=keyid,issuer\\n' \
  > /out/server.ext
openssl req -new {leaf_args} -keyout /out/server.key -out /out/server.csr \
  -nodes -subj /CN=localhost {leaf_hash}
openssl x509 -req -in /out/server.csr -CA /out/server_root.crt \
  -CAkey /out/server_root.key -CAcreateserial -out /out/server.crt \
  -not_before {CERT_NOT_BEFORE} -not_after {CERT_NOT_AFTER} \
  -extfile /out/server.ext {issuer_hash}
cp /out/server.crt /out/server_chain.crt
openssl verify -purpose sslserver -CAfile /out/server_root.crt /out/server.crt
"""
    _docker_script(cache, script, log)
    _copy_files(cache, output, cached_required)
    shutil.copy2(client_dir / "client_ca.crt", output / "client_ca.crt")
    shutil.copy2(client_dir / "client_ca.der", output / "client_ca.der")
    write_case_configs(case, output)


def generate_hash_based_server_case(
    signature: str,
    output: Path,
    client_dir: Path,
    log: Path,
) -> None:
    output.mkdir(parents=True, exist_ok=True)
    _docker_script(output, f"hbs_certgen {shlex.quote(signature)} /out", log)
    shutil.copy2(client_dir / "client_ca.crt", output / "client_ca.crt")
    shutil.copy2(client_dir / "client_ca.der", output / "client_ca.der")


def write_case_configs(case: dict[str, str], output: Path) -> None:
    kem = KEMS_BY_NAME[case["kex_group"]]
    client_sigalgs = _client_signature_algorithms(
        case.get("certificate_verify_alg") or case.get("cert_sig_alg", "ECDSA-P-256")
    )
    max_send_fragment = (
        "MaxSendFragment = 2048\n"
        if case.get("cert_sig_alg", "").startswith("SLH-DSA-SHAKE-")
        else ""
    )
    (output / "openssl.cnf").write_text(
        "openssl_conf = openssl_init\n\n"
        "[openssl_init]\nproviders = provider_sect\nssl_conf = ssl_sect\n\n"
        "[provider_sect]\ndefault = default_sect\noqsprovider = oqsprovider_sect\n\n"
        "[default_sect]\nactivate = 1\n\n"
        "[oqsprovider_sect]\nactivate = 1\n"
        "module = /usr/local/lib/ossl-modules/oqsprovider.so\n\n"
        "[ssl_sect]\nsystem_default = system_default_sect\n\n"
        "[system_default_sect]\nMinProtocol = TLSv1.3\n"
        f"Groups = {kem.openssl_group}\n"
        f"{max_send_fragment}"
        f"ClientSignatureAlgorithms = {client_sigalgs}\n"
    )
    (output / "mosquitto.conf").write_text(
        "listener 8883\n"
        "allow_anonymous true\n"
        "cafile __REMOTE_CASE_DIR__/client_ca.crt\n"
        "certfile __REMOTE_CASE_DIR__/server_chain.crt\n"
        "keyfile __REMOTE_CASE_DIR__/server.key\n"
        "require_certificate true\n"
        "use_identity_as_username true\n"
    )


def c_array(name: str, data: bytes) -> str:
    rows = []
    values = [f"0x{value:02x}" for value in data]
    for offset in range(0, len(values), 12):
        rows.append("    " + ", ".join(values[offset:offset + 12]))
    return f"static const unsigned char {name}[] = {{\n" + ",\n".join(rows) + "\n};\n"


def generate_universal_header(
    client_dir: Path,
    case_dirs: list[tuple[str, Path]],
    output: Path,
) -> None:
    roots: list[tuple[str, bytes]] = [
        ("benchmark_server_root", (client_dir / "server_root.der").read_bytes())
    ]
    seen = {roots[0][1]}
    for case_id, case_dir in case_dirs:
        root = case_dir / "server_root.der"
        if not root.exists():
            continue
        data = root.read_bytes()
        if data in seen:
            continue
        seen.add(data)
        roots.append((f"benchmark_server_root_{len(roots)}", data))

    parts = [
        "#ifndef BENCHMARK_CREDENTIALS_H\n#define BENCHMARK_CREDENTIALS_H\n\n",
        "#include <stddef.h>\n\n",
        c_array("benchmark_client_cert", (client_dir / "client_cert.der").read_bytes()),
        c_array("benchmark_client_key", (client_dir / "client_key.der").read_bytes()),
    ]
    parts.extend(c_array(name, data) for name, data in roots)
    parts.extend(
        [
            "\nstruct benchmark_ca_entry { const unsigned char *data; size_t length; };\n",
            "static const struct benchmark_ca_entry benchmark_ca_bundle[] = {\n",
            ",\n".join(
                f"    {{ {name}, sizeof({name}) }}"
                for name, _data in roots
            ),
            "\n};\n",
            "#define BENCHMARK_CA_COUNT "
            "(sizeof(benchmark_ca_bundle) / sizeof(benchmark_ca_bundle[0]))\n",
            "#endif\n",
        ]
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(parts))
