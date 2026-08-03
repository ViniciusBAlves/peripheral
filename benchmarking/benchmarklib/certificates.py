from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import hashlib
import json
from pathlib import Path

from .algorithms import KEMS_BY_NAME, SIGNATURES_BY_NAME, Signature, slug
from .server_backends import HASH_BASED_SIGNATURES


IMAGE = "peripheral-pqc-openssl:3.8"
ROOT = Path(__file__).resolve().parents[1]
CERT_CACHE = ROOT / "work" / "certificate-cache" / "v5-three-tier"
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
    """Generate the fixed ECDSA P-256 identity used by optional mTLS runs."""
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


def c_array(name: str, data: bytes) -> str:
    rows = []
    values = [f"0x{value:02x}" for value in data]
    for offset in range(0, len(values), 12):
        rows.append("    " + ", ".join(values[offset:offset + 12]))
    return f"static const unsigned char {name}[] = {{\n" + ",\n".join(rows) + "\n};\n"


# The normal server PKI remains independent from the optional fixed mTLS
# client identity generated above.
PUBLIC_CHAIN_FILES = (
    "server_root.crt", "server_root.der", "server_intermediate.crt",
    "server_intermediate.der", "server.crt", "server.der", "server.key",
    "server_chain.crt",
)


def _case_algorithms(
    case: dict[str, str],
) -> tuple[Signature, Signature, Signature]:
    root_name = case.get("root_sig_alg") or case["cert_sig_alg"]
    intermediate_name = case.get("intermediate_sig_alg") or case["cert_sig_alg"]
    leaf_name = case.get("leaf_sig_alg") or case["cert_sig_alg"]
    return (
        SIGNATURES_BY_NAME[root_name],
        SIGNATURES_BY_NAME[intermediate_name],
        SIGNATURES_BY_NAME[leaf_name],
    )


def _generate_openssl_root(signature: Signature, output: Path, log: Path) -> None:
    required = ("server_root.crt", "server_root.der", "server_root.key")
    if _all_present(output, required) and _cert_is_valid(output / "server_root.crt"):
        return
    shutil.rmtree(output, ignore_errors=True)
    output.mkdir(parents=True, exist_ok=True)
    _docker_script(output, f"""
openssl req -x509 -new {_key_args(signature.issuer_key_type)} \
  -keyout /out/server_root.key -out /out/server_root.crt -nodes \
  -subj /CN={signature.name}_Root \
  -not_before {CERT_NOT_BEFORE} -not_after {CERT_NOT_AFTER} \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign \
  {_hash_arg(signature.issuer_key_type)} {_signature_options(signature.issuer_key_type)}
openssl x509 -in /out/server_root.crt -outform DER -out /out/server_root.der
""", log)


def _generate_openssl_three_tier(
    root: Signature,
    intermediate: Signature,
    leaf: Signature,
    output: Path,
    root_cache: Path,
    log: Path,
) -> None:
    """Create root -> subordinate CA -> server leaf with no root in the chain."""
    _generate_openssl_root(root, root_cache, log)
    output.mkdir(parents=True, exist_ok=True)
    for name in ("server_root.crt", "server_root.der", "server_root.key"):
        shutil.copy2(root_cache / name, output / name)
    intermediate_args = _key_args(intermediate.issuer_key_type)
    intermediate_hash = _hash_arg(intermediate.issuer_key_type)
    leaf_args = _key_args(leaf.leaf_key_type)
    leaf_hash = _hash_arg(leaf.leaf_key_type)
    _docker_script(output, f"""
printf 'basicConstraints=critical,CA:TRUE\\nkeyUsage=critical,keyCertSign,cRLSign\\nsubjectKeyIdentifier=hash\\nauthorityKeyIdentifier=keyid,issuer\\n' > /out/intermediate.ext
printf 'basicConstraints=critical,CA:FALSE\\nkeyUsage=critical,digitalSignature\\nextendedKeyUsage=critical,serverAuth\\nsubjectAltName=DNS:localhost,IP:127.0.0.1\\nsubjectKeyIdentifier=hash\\nauthorityKeyIdentifier=keyid,issuer\\n' > /out/server.ext
openssl req -new {intermediate_args} -keyout /out/server_intermediate.key \
  -out /out/server_intermediate.csr -nodes \
  -subj /CN={intermediate.name}_Intermediate {intermediate_hash}
openssl x509 -req -in /out/server_intermediate.csr -CA /out/server_root.crt \
  -CAkey /out/server_root.key -CAcreateserial -out /out/server_intermediate.crt \
  -not_before {CERT_NOT_BEFORE} -not_after {CERT_NOT_AFTER} \
  -extfile /out/intermediate.ext {_hash_arg(root.issuer_key_type)} \
  {_signature_options(root.issuer_key_type)}
openssl req -new {leaf_args} -keyout /out/server.key -out /out/server.csr \
  -nodes -subj /CN=localhost {leaf_hash}
openssl x509 -req -in /out/server.csr -CA /out/server_intermediate.crt \
  -CAkey /out/server_intermediate.key -CAcreateserial -out /out/server.crt \
  -not_before {CERT_NOT_BEFORE} -not_after {CERT_NOT_AFTER} \
  -extfile /out/server.ext {intermediate_hash} \
  {_signature_options(intermediate.issuer_key_type)}
cat /out/server.crt /out/server_intermediate.crt > /out/server_chain.crt
openssl x509 -in /out/server_intermediate.crt -outform DER -out /out/server_intermediate.der
openssl x509 -in /out/server.crt -outform DER -out /out/server.der
openssl verify -purpose sslserver -CAfile /out/server_root.crt \
  -untrusted /out/server_intermediate.crt /out/server.crt
""", log)


def generate_hash_based_server_case(
    root_signature: str,
    intermediate_signature: str,
    leaf_signature: str,
    output: Path,
    root_cache: Path,
    log: Path,
) -> None:
    """Use wolfSSL for stateful LMS/XMSS X.509 issuers."""
    output.mkdir(parents=True, exist_ok=True)
    root_cache.mkdir(parents=True, exist_ok=True)
    run([
        "docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
        "-v", f"{output.resolve()}:/out",
        "-v", f"{root_cache.resolve()}:/root-cache",
        IMAGE, "hbs_certgen", root_signature, intermediate_signature,
        leaf_signature,
        "/root-cache", "/out",
    ], log=log)


def write_case_configs(case: dict[str, str], output: Path) -> None:
    kem = KEMS_BY_NAME[case["kex_group"]]
    root, _intermediate, leaf = _case_algorithms(case)
    max_send_fragment = (
        "MaxSendFragment = 2048\n"
        if root.name.startswith("SLH-DSA-SHAKE-") else ""
    )
    (output / "pki_metadata.json").write_text(json.dumps({
        "pki_chain_id": case.get("pki_chain_id", f"homogeneous_{slug(leaf.name)}"),
        "pki_kind": case.get("pki_kind", "homogeneous"),
        "root_sig_alg": root.name,
        "intermediate_sig_alg": case.get("intermediate_sig_alg") or leaf.name,
        "leaf_sig_alg": leaf.name,
    }, indent=2) + "\n")
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
        f"Groups = {kem.openssl_group}\n{max_send_fragment}"
        f"SignatureAlgorithms = {leaf.tls_signature_scheme}\n"
    )
    (output / "mosquitto.conf").write_text(
        "listener 8883\nallow_anonymous true\n"
        "certfile __REMOTE_CASE_DIR__/server_chain.crt\n"
        "keyfile __REMOTE_CASE_DIR__/server.key\n"
        "require_certificate false\n"
    )
    (output / "mosquitto-transfer.conf").write_text(
        "per_listener_settings true\n"
        "listener 8883\nallow_anonymous true\n"
        "certfile __REMOTE_CASE_DIR__/server_chain.crt\n"
        "keyfile __REMOTE_CASE_DIR__/server.key\n"
        "require_certificate false\n"
        "listener 18884 127.0.0.1\nallow_anonymous true\n"
    )
    if (output / "client_ca.crt").exists():
        mtls_openssl = (output / "openssl.cnf").read_text().replace(
            f"SignatureAlgorithms = {leaf.tls_signature_scheme}\n",
            f"SignatureAlgorithms = {leaf.tls_signature_scheme}\n"
            "ClientSignatureAlgorithms = ecdsa_secp256r1_sha256\n",
        )
        (output / "openssl-mtls.cnf").write_text(mtls_openssl)
        (output / "mosquitto-mtls.conf").write_text(
            "listener 8883\nallow_anonymous true\n"
            "cafile __REMOTE_CASE_DIR__/client_ca.crt\n"
            "certfile __REMOTE_CASE_DIR__/server_chain.crt\n"
            "keyfile __REMOTE_CASE_DIR__/server.key\n"
            "require_certificate true\n"
            "use_identity_as_username true\n"
        )
        (output / "mosquitto-transfer-mtls.conf").write_text(
            "per_listener_settings true\n"
            "listener 8883\nallow_anonymous true\n"
            "cafile __REMOTE_CASE_DIR__/client_ca.crt\n"
            "certfile __REMOTE_CASE_DIR__/server_chain.crt\n"
            "keyfile __REMOTE_CASE_DIR__/server.key\n"
            "require_certificate true\n"
            "use_identity_as_username true\n"
            "listener 18884 127.0.0.1\nallow_anonymous true\n"
    )


def generate_server_case(
    case: dict[str, str], output: Path, log: Path, *, client_dir: Path | None = None,
) -> None:
    """Create a cached root -> intermediate -> leaf server PKI for one chain."""
    root, intermediate, leaf = _case_algorithms(case)
    chain_id = case.get("pki_chain_id") or f"homogeneous_{slug(leaf.name)}"
    cache = CERT_CACHE / "chains" / chain_id
    root_cache = CERT_CACHE / "roots" / slug(root.name)
    valid = (
        _all_present(cache, PUBLIC_CHAIN_FILES)
        and _cert_is_valid(cache / "server_root.crt")
        and _cert_is_valid(cache / "server_intermediate.crt")
        and _cert_is_valid(cache / "server.crt")
    )
    if not valid:
        shutil.rmtree(cache, ignore_errors=True)
        _append_log(log, f"[cert-cache] Generating three-tier PKI {chain_id}")
        if root.name in HASH_BASED_SIGNATURES:
            generate_hash_based_server_case(
                root.name, intermediate.name, leaf.name, cache, root_cache, log,
            )
        else:
            _generate_openssl_three_tier(
                root, intermediate, leaf, cache, root_cache, log,
            )
    else:
        _append_log(log, f"[cert-cache] Reusing three-tier PKI {chain_id}")
    _copy_files(cache, output, PUBLIC_CHAIN_FILES)
    if client_dir is not None:
        for name in ("client_ca.crt", "client_ca.der"):
            shutil.copy2(client_dir / name, output / name)
    write_case_configs(case, output)


def generate_universal_header(
    case_dirs: list[tuple[str, Path]],
    output: Path,
    *,
    root_algorithms: set[str] | None = None,
    client_dir: Path | None = None,
) -> None:
    """Embed selected roots and, only for mTLS builds, the client identity."""
    roots: list[tuple[str, str, bytes]] = []
    profiles: list[Signature] = []
    seen_roots: set[bytes] = set()
    seen_profiles: set[str] = set()
    parts = [
        "#ifndef BENCHMARK_CREDENTIALS_H\n#define BENCHMARK_CREDENTIALS_H\n\n",
        "#include <stddef.h>\n#include <stdint.h>\n\n",
    ]
    if client_dir is not None:
        parts.extend([
            "#define BENCHMARK_HAS_CLIENT_IDENTITY 1\n",
            c_array(
                "benchmark_client_cert",
                (client_dir / "client_cert.der").read_bytes(),
            ),
            c_array(
                "benchmark_client_key",
                (client_dir / "client_key.der").read_bytes(),
            ),
        ])
    else:
        parts.append("#define BENCHMARK_HAS_CLIENT_IDENTITY 0\n")
    for _case_id, case_dir in case_dirs:
        metadata_path = case_dir / "pki_metadata.json"
        root_path = case_dir / "server_root.der"
        if not metadata_path.exists() or not root_path.exists():
            continue
        metadata = json.loads(metadata_path.read_text())
        root_id = metadata["root_sig_alg"]
        root_data = root_path.read_bytes()
        if (
            (root_algorithms is None or root_id in root_algorithms)
            and root_data not in seen_roots
        ):
            array_name = f"benchmark_server_root_{len(roots)}"
            roots.append((root_id, array_name, root_data))
            seen_roots.add(root_data)
        leaf = SIGNATURES_BY_NAME[metadata["leaf_sig_alg"]]
        if leaf.name not in seen_profiles:
            profiles.append(leaf)
            seen_profiles.add(leaf.name)
    parts.extend(c_array(name, data) for _root_id, name, data in roots)
    parts.extend([
        "\nstruct benchmark_ca_entry { const char *id; const unsigned char *data; size_t length; };\n",
        "static const struct benchmark_ca_entry benchmark_ca_bundle[] = {\n",
        ",\n".join(
            f"    {{ \"{root_id}\", {name}, sizeof({name}) }}"
            for root_id, name, _data in roots
        ),
        "\n};\n#define BENCHMARK_CA_COUNT "
        "(sizeof(benchmark_ca_bundle) / sizeof(benchmark_ca_bundle[0]))\n",
        "\nstruct benchmark_signature_profile { const char *id; const char *signature_scheme; uint16_t signature_scheme_id; };\n",
        "static const struct benchmark_signature_profile benchmark_signature_profiles[] = {\n",
        ",\n".join(
            f"    {{ \"{item.name}\", \"{item.tls_signature_scheme}\", "
            f"0x{item.tls_signature_scheme_id:04x} }}" for item in profiles
        ),
        "\n};\n#define BENCHMARK_SIGNATURE_PROFILE_COUNT "
        "(sizeof(benchmark_signature_profiles) / sizeof(benchmark_signature_profiles[0]))\n",
        "#endif\n",
    ])
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(parts))
