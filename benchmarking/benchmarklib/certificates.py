from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

from .algorithms import KEMS_BY_NAME, SIGNATURES_BY_NAME, Signature


IMAGE = "peripheral-pqc-openssl:3.5"


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
    probe = subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True)
    if probe.returncode:
        run(["docker", "build", "-t", IMAGE, "-f", str(dockerfile), str(dockerfile.parent)], log=log)
    run(
        [
            "docker", "run", "--rm", IMAGE, "sh", "-ec",
            "openssl version; "
            "openssl list -kem-algorithms | grep -Eq 'MLKEM512|ML-KEM-512'; "
            "openssl list -signature-algorithms | grep -q 'SLH-DSA-SHAKE-256s'",
        ],
        log=log,
    )


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


def generate_client_identity(output: Path, log: Path) -> None:
    required = (
        "client_ca.crt", "client.crt", "client.key", "client_ca.der",
        "client_cert.der", "client_key.der", "server_root.crt",
        "server_root.key", "server_root.der",
    )
    if all((output / name).exists() for name in required):
        return
    script = """
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /out/client_ca.key -out /out/client_ca.crt -nodes \
  -subj /CN=Peripheral_Benchmark_Client_CA -days 3650 \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /out/client.key -out /out/client.csr -nodes -subj /CN=nrf52840-benchmark
openssl x509 -req -in /out/client.csr -CA /out/client_ca.crt \
  -CAkey /out/client_ca.key -CAcreateserial -out /out/client.crt -days 3650
openssl x509 -in /out/client_ca.crt -outform DER -out /out/client_ca.der
openssl x509 -in /out/client.crt -outform DER -out /out/client_cert.der
openssl pkey -in /out/client.key -outform DER -out /out/client_key.der
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout /out/server_root.key -out /out/server_root.crt -nodes \
  -subj /CN=Peripheral_Benchmark_Server_Root -days 3650 \
  -addext basicConstraints=critical,CA:TRUE \
  -addext keyUsage=critical,keyCertSign,cRLSign
openssl x509 -in /out/server_root.crt -outform DER -out /out/server_root.der
"""
    _docker_script(output, script, log)


def generate_server_case(case: dict[str, str], output: Path, client_dir: Path, log: Path) -> None:
    required = ("server_intermediate.crt", "server.crt", "server.key",
                "server_chain.crt", "openssl.cnf", "mosquitto.conf")
    if all((output / name).exists() for name in required):
        return
    signature: Signature = SIGNATURES_BY_NAME[case["cert_sig_alg"]]
    kem = KEMS_BY_NAME[case["kex_group"]]
    issuer_args = _key_args(signature.issuer_key_type)
    leaf_args = _key_args(signature.leaf_key_type)
    issuer_hash = _hash_arg(signature.issuer_key_type)
    leaf_hash = _hash_arg(signature.leaf_key_type)
    output.mkdir(parents=True, exist_ok=True)
    shutil.copy2(client_dir / "server_root.crt", output / "server_root.crt")
    shutil.copy2(client_dir / "server_root.key", output / "server_root.key")
    script = f"""
printf 'basicConstraints=critical,CA:TRUE\\nkeyUsage=critical,keyCertSign,cRLSign\\n' \
  > /out/intermediate.ext
openssl req -new {issuer_args} -keyout /out/server_intermediate.key \
  -out /out/server_intermediate.csr -nodes -subj /CN={signature.name}_Intermediate \
  {issuer_hash}
openssl x509 -req -in /out/server_intermediate.csr -CA /out/server_root.crt \
  -CAkey /out/server_root.key -CAcreateserial -out /out/server_intermediate.crt \
  -days 3650 -extfile /out/intermediate.ext
openssl req -new {leaf_args} -keyout /out/server.key -out /out/server.csr \
  -nodes -subj /CN=localhost {leaf_hash}
openssl x509 -req -in /out/server.csr -CA /out/server_intermediate.crt \
  -CAkey /out/server_intermediate.key -CAcreateserial -out /out/server.crt \
  -days 3650 {issuer_hash}
cat /out/server.crt /out/server_intermediate.crt > /out/server_chain.crt
"""
    _docker_script(output, script, log)
    shutil.copy2(client_dir / "client_ca.crt", output / "client_ca.crt")
    write_case_configs(case, output)


def write_case_configs(case: dict[str, str], output: Path) -> None:
    kem = KEMS_BY_NAME[case["kex_group"]]
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
    parts = [
        "#ifndef BENCHMARK_CREDENTIALS_H\n#define BENCHMARK_CREDENTIALS_H\n\n",
        "#include <stddef.h>\n\n",
        c_array("benchmark_client_cert", (client_dir / "client_cert.der").read_bytes()),
        c_array("benchmark_client_key", (client_dir / "client_key.der").read_bytes()),
        c_array("benchmark_server_root", (client_dir / "server_root.der").read_bytes()),
    ]
    parts.extend(
        [
            "\nstruct benchmark_ca_entry { const unsigned char *data; size_t length; };\n",
            "static const struct benchmark_ca_entry benchmark_ca_bundle[] = {\n",
            "    { benchmark_server_root, sizeof(benchmark_server_root) }",
            "\n};\n",
            "#define BENCHMARK_CA_COUNT "
            "(sizeof(benchmark_ca_bundle) / sizeof(benchmark_ca_bundle[0]))\n",
            "#endif\n",
        ]
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("".join(parts))
