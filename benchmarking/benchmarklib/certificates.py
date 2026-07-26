from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import hashlib
from pathlib import Path

from .algorithms import KEMS_BY_NAME, SIGNATURES_BY_NAME, Signature, slug
from .server_backends import HASH_BASED_SIGNATURES


IMAGE = "peripheral-pqc-openssl:3.6"
ROOT = Path(__file__).resolve().parents[1]
CERT_CACHE = ROOT / "work" / "certificate-cache" / "v4-direct-root-mtls"
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
        "openssl list -signature-algorithms | grep -q 'SLH-DSA-SHAKE-256f'; "
        "command -v hbs_certgen",
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
    bits = _rsa_bits(key_type)
    if bits:
        return f"-newkey rsa:{bits}"
    if key_type.startswith("ec:"):
        return f"-newkey ec -pkeyopt ec_paramgen_curve:{key_type.split(':', 1)[1]}"
    return f"-newkey {key_type}"


def _hash_arg(key_type: str) -> str:
    bits = _rsa_bits(key_type)
    if not bits:
        return ""
    return "-sha256" if bits <= 3072 else "-sha384" if bits <= 7680 else "-sha512"


def _signature_options(key_type: str) -> str:
    if _rsa_bits(key_type):
        return "-sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest"
    return ""


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


def _shared_client_key(signature: Signature, log: Path) -> Path:
    cache = (
        CERT_CACHE / "client-keys" /
        slug(signature.tls_signature_scheme)
    )
    required = ("client.key", "client_key.der")
    if _all_present(cache, required):
        return cache
    shutil.rmtree(cache, ignore_errors=True)
    cache.mkdir(parents=True, exist_ok=True)
    key_args = _key_args(signature.leaf_key_type)
    hash_arg = _hash_arg(signature.leaf_key_type)
    _append_log(
        log,
        f"[cert-cache] Generating shared {signature.tls_signature_scheme} "
        f"client key into {cache}",
    )
    _docker_script(
        cache,
        f"""
openssl req -new {key_args} -keyout /out/client.key \
  -out /out/client-key-only.csr -nodes -subj /CN=shared-client-key {hash_arg}
openssl pkey -in /out/client.key -outform DER -out /out/client_key.der
""",
        log,
    )
    return cache


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


def _digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()[:16]


def generate_client_identity(output: Path, log: Path) -> None:
    """Generate the legacy host-only certificate benchmark trust anchor."""
    required = (
        "client_ca.crt", "client.crt", "client.key", "client_ca.der",
        "client_cert.der", "client_key.der", "server_root.crt",
        "server_root.key", "server_root.der",
    )
    if _all_present(output, required):
        return
    output.mkdir(parents=True, exist_ok=True)
    script = f"""
printf 'basicConstraints=critical,CA:FALSE\\nkeyUsage=critical,digitalSignature\\nextendedKeyUsage=critical,clientAuth\\n' > /out/client.ext
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /out/client_ca.key -out /out/client_ca.crt -nodes \
  -subj /CN=Peripheral_Benchmark_Client_CA \
  -not_before {CERT_NOT_BEFORE} -not_after {CERT_NOT_AFTER} \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /out/client.key -out /out/client.csr -nodes \
  -subj /CN=nrf5340-benchmark
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
"""
    _docker_script(output, script, log)


def generate_server_case(case: dict[str, str], output: Path, client_dir: Path, log: Path) -> None:
    signature: Signature = SIGNATURES_BY_NAME[case["cert_sig_alg"]]
    cached_required = (
        "server_root.crt", "server_root.der", "server.crt", "server.key",
        "server_chain.crt", "client_ca.crt", "client_ca.der", "client.crt",
        "client.key", "client_cert.der", "client_key.der",
    )
    output_required = (
        *cached_required, "client_ca.crt", "client_ca.der",
        "openssl.cnf", "mosquitto.conf", "mosquitto-mtls.conf",
    )
    if (
        _all_present(output, output_required)
        and _cert_is_valid(output / "server_root.crt")
        and _cert_is_valid(output / "server.crt")
        and _cert_is_valid(output / "client.crt")
    ):
        write_case_configs(case, output)
        return
    cache = CERT_CACHE / "identity" / slug(signature.name)
    if (
        _all_present(cache, cached_required)
        and _cert_is_valid(cache / "server_root.crt")
        and _cert_is_valid(cache / "server.crt")
        and _cert_is_valid(cache / "client.crt")
    ):
        _append_log(log, f"[cert-cache] Reusing {signature.name} direct-root PKI from {cache}")
        _copy_files(cache, output, cached_required)
        write_case_configs(case, output)
        return
    _append_log(log, f"[cert-cache] Generating {signature.name} direct-root PKI into {cache}")
    shutil.rmtree(cache, ignore_errors=True)
    cache.mkdir(parents=True, exist_ok=True)
    shared_key = _shared_client_key(signature, log)
    shutil.copy2(shared_key / "client.key", cache / "client.key")
    shutil.copy2(shared_key / "client_key.der", cache / "client_key.der")
    issuer_args = _key_args(signature.issuer_key_type)
    leaf_args = _key_args(signature.leaf_key_type)
    issuer_hash = _hash_arg(signature.issuer_key_type)
    leaf_hash = _hash_arg(signature.leaf_key_type)
    issuer_sigopts = _signature_options(signature.issuer_key_type)
    if signature.name in HASH_BASED_SIGNATURES:
        generate_hash_based_server_case(signature.name, cache, client_dir, log)
        _copy_files(cache, output, cached_required)
        write_case_configs(case, output)
        return
    script = f"""
printf 'basicConstraints=critical,CA:FALSE\\nkeyUsage=critical,digitalSignature,keyEncipherment\\nextendedKeyUsage=critical,serverAuth\\nsubjectAltName=DNS:localhost,IP:127.0.0.1\\nsubjectKeyIdentifier=hash\\nauthorityKeyIdentifier=keyid,issuer\\n' \
  > /out/server.ext
printf 'basicConstraints=critical,CA:FALSE\\nkeyUsage=critical,digitalSignature\\nextendedKeyUsage=critical,clientAuth\\nsubjectKeyIdentifier=hash\\nauthorityKeyIdentifier=keyid,issuer\\n' \
  > /out/client.ext
openssl req -x509 -new {issuer_args} -keyout /out/server_root.key \
  -out /out/server_root.crt -nodes -subj /CN={signature.name}_Root \
  -not_before {CERT_NOT_BEFORE} -not_after {CERT_NOT_AFTER} \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign {issuer_hash} {issuer_sigopts}
openssl req -new {leaf_args} -keyout /out/server.key -out /out/server.csr \
  -nodes -subj /CN=localhost {leaf_hash}
openssl x509 -req -in /out/server.csr -CA /out/server_root.crt \
  -CAkey /out/server_root.key -CAcreateserial -out /out/server.crt \
  -not_before {CERT_NOT_BEFORE} -not_after {CERT_NOT_AFTER} \
  -extfile /out/server.ext {issuer_hash} {issuer_sigopts}
openssl req -new -key /out/client.key -out /out/client.csr \
  -subj /CN=nrf5340-benchmark {leaf_hash}
openssl x509 -req -in /out/client.csr -CA /out/server_root.crt \
  -CAkey /out/server_root.key -CAcreateserial -out /out/client.crt \
  -not_before {CERT_NOT_BEFORE} -not_after {CERT_NOT_AFTER} \
  -extfile /out/client.ext {issuer_hash} {issuer_sigopts}
cat /out/server.crt /out/server_root.crt > /out/server_chain.crt
cp /out/server_root.crt /out/client_ca.crt
openssl x509 -in /out/server_root.crt -outform DER -out /out/server_root.der
cp /out/server_root.der /out/client_ca.der
openssl x509 -in /out/client.crt -outform DER -out /out/client_cert.der
openssl pkey -in /out/client.key -outform DER -out /out/client_key.der
openssl verify -purpose sslserver -CAfile /out/server_root.crt /out/server.crt
openssl verify -purpose sslclient -CAfile /out/server_root.crt /out/client.crt
"""
    _docker_script(cache, script, log)
    _copy_files(cache, output, cached_required)
    write_case_configs(case, output)


def generate_hash_based_server_case(
    signature: str,
    output: Path,
    client_dir: Path,
    log: Path,
) -> None:
    output.mkdir(parents=True, exist_ok=True)
    _docker_script(output, f"hbs_certgen {shlex.quote(signature)} /out", log)
    shutil.copy2(output / "server_root.crt", output / "client_ca.crt")
    shutil.copy2(output / "server_root.der", output / "client_ca.der")


def write_case_configs(case: dict[str, str], output: Path) -> None:
    kem = KEMS_BY_NAME[case["kex_group"]]
    signature = SIGNATURES_BY_NAME[case["cert_sig_alg"]]
    (output / "client_identity.txt").write_text(f"{signature.name}\n")
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
        "Options = -SessionTicket\n"
        f"Groups = {kem.openssl_group}\n"
        f"{max_send_fragment}"
        f"SignatureAlgorithms = {signature.tls_signature_scheme}\n"
        f"ClientSignatureAlgorithms = {signature.tls_signature_scheme}\n"
    )
    (output / "mosquitto.conf").write_text(
        "listener 8883\n"
        "allow_anonymous true\n"
        "certfile __REMOTE_CASE_DIR__/server_chain.crt\n"
        "keyfile __REMOTE_CASE_DIR__/server.key\n"
        "require_certificate false\n"
    )
    (output / "mosquitto-mtls.conf").write_text(
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
    roots: list[tuple[str, bytes]] = []
    identities: list[tuple[Signature, str, str]] = []
    seen_roots: set[bytes] = set()
    seen_identities: set[str] = set()
    key_arrays: dict[bytes, str] = {}
    parts = [
        "#ifndef BENCHMARK_CREDENTIALS_H\n#define BENCHMARK_CREDENTIALS_H\n\n",
        "#include <stddef.h>\n#include <stdint.h>\n\n",
    ]
    for case_id, case_dir in case_dirs:
        identity_file = case_dir / "client_identity.txt"
        if identity_file.exists():
            signature = SIGNATURES_BY_NAME.get(identity_file.read_text().strip())
        else:
            signature_name = case_id.split("__", 1)[-1]
            signature = next(
                (
                    item for item in SIGNATURES_BY_NAME.values()
                    if slug(item.name) == signature_name
                ),
                None,
            )
        if signature is None:
            continue
        root = case_dir / "server_root.der"
        cert = case_dir / "client_cert.der"
        key = case_dir / "client_key.der"
        if not root.exists() or not cert.exists() or not key.exists():
            continue
        root_data = root.read_bytes()
        if root_data not in seen_roots:
            root_name = f"benchmark_server_root_{len(roots)}"
            seen_roots.add(root_data)
            roots.append((root_name, root_data))
        if signature.name not in seen_identities:
            index = len(identities)
            cert_name = f"benchmark_client_cert_{index}"
            key_data = key.read_bytes()
            key_name = key_arrays.get(key_data, "")
            parts.append(c_array(cert_name, cert.read_bytes()))
            if not key_name:
                key_name = f"benchmark_client_key_{len(key_arrays)}"
                parts.append(c_array(key_name, key_data))
                key_arrays[key_data] = key_name
            identities.append((signature, cert_name, key_name))
            seen_identities.add(signature.name)

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
            "\nstruct benchmark_identity_entry {\n"
            "    const char *id;\n"
            "    const char *signature_scheme;\n"
            "    uint16_t signature_scheme_id;\n"
            "    const unsigned char *certificate;\n"
            "    size_t certificate_length;\n"
            "    const unsigned char *private_key;\n"
            "    size_t private_key_length;\n"
            "};\n",
            "static const struct benchmark_identity_entry "
            "benchmark_client_identities[] = {\n",
            ",\n".join(
                "    { "
                f"\"{signature.name}\", \"{signature.tls_signature_scheme}\", "
                f"0x{signature.tls_signature_scheme_id:04x}, "
                f"{cert_name}, sizeof({cert_name}), "
                f"{key_name}, sizeof({key_name}) "
                "}"
                for signature, cert_name, key_name in identities
            ),
            "\n};\n",
            "#define BENCHMARK_IDENTITY_COUNT "
            "(sizeof(benchmark_client_identities) / "
            "sizeof(benchmark_client_identities[0]))\n",
            "#endif\n",
        ]
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(parts))
