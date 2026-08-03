from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

PQM4_URL = "https://github.com/mupq/pqm4.git"
PQM4_COMMIT = "cc2c1b992b602d285bd15991a566d5f17b34c1fa"


def run_logged(
    command: list[str],
    log: Path,
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a") as stream:
        if cwd is not None:
            stream.write(f"$ cd {cwd}\n")
        stream.write(f"$ {' '.join(command)}\n")
        proc = subprocess.run(
            command,
            cwd=cwd,
            env=env,
            text=True,
            stdout=stream,
            stderr=subprocess.STDOUT,
        )
    if proc.returncode:
        raise subprocess.CalledProcessError(proc.returncode, command)


def ensure_pqm4(directory: Path, log: Path) -> None:
    if not (directory / ".git").exists():
        run_logged(
            ["git", "clone", "--recursive", PQM4_URL, str(directory)],
            log,
        )
    head = subprocess.run(
        ["git", "-C", str(directory), "rev-parse", "HEAD"],
        check=True, text=True, capture_output=True,
    ).stdout.strip()
    if head != PQM4_COMMIT:
        run_logged(["git", "-C", str(directory), "fetch", "origin", PQM4_COMMIT], log)
        run_logged(
            ["git", "-C", str(directory), "checkout", "--detach", PQM4_COMMIT],
            log,
        )
    run_logged(
        ["git", "-C", str(directory), "submodule", "update", "--init", "--recursive"],
        log,
    )


def toolchain_root_from_nrfutil(nrfutil: str) -> Path | None:
    path = Path(nrfutil)
    for parent in (path.parent, *path.parents):
        if (parent / "environment.json").exists():
            return parent
    return None


def toolchain_environment(nrfutil: str) -> dict[str, str]:
    env = os.environ.copy()
    root = toolchain_root_from_nrfutil(nrfutil)
    if root is None:
        return env
    environment_json = root / "environment.json"
    values = json.loads(environment_json.read_text())
    for item in values.get("env_vars", []):
        key = item["key"]
        if item["type"] == "string":
            env[key] = item["value"]
            continue
        if item["type"] != "relative_paths":
            continue
        paths = [str(root / value) for value in item["values"]]
        treatment = item.get("existing_value_treatment", "overwrite")
        if treatment == "prepend_to" and env.get(key):
            env[key] = os.pathsep.join([*paths, env[key]])
        else:
            env[key] = os.pathsep.join(paths)
    return env


def has_sdk_manager(nrfutil: str) -> bool:
    try:
        proc = subprocess.run(
            [nrfutil, "list"],
            env=toolchain_environment(nrfutil),
            text=True,
            capture_output=True,
            check=False,
        )
    except OSError:
        return False
    return proc.returncode == 0 and "sdk-manager" in proc.stdout


def west_command(
    *,
    nrfutil: str,
    ncs_version: str,
    ncs_chdir: str,
    west_args: list[str],
) -> tuple[list[str], Path | None, dict[str, str] | None]:
    if has_sdk_manager(nrfutil):
        return (
            [
                nrfutil, "sdk-manager", "toolchain", "launch",
                "--ncs-version", ncs_version,
                "--chdir", ncs_chdir,
                "--", "west", *west_args,
            ],
            None,
            None,
        )
    return ["west", *west_args], Path(ncs_chdir), toolchain_environment(nrfutil)


def build(
    *,
    firmware_dir: Path,
    build_dir: Path,
    generated_dir: Path,
    log: Path,
    nrfutil: str,
    ncs_version: str,
    ncs_chdir: str,
    board: str,
    mlkem_backend: str,
    pqm4_dir: Path | None,
    large_rsa: bool = False,
    power_markers: bool = False,
    ble_telemetry: bool = False,
    mtls_mode: bool = False,
    certificate_gen: bool = False,
    kem_benchmark: bool = False,
    transfer_mode: bool = False,
) -> None:
    if certificate_gen and kem_benchmark:
        raise ValueError("certificate_gen and kem_benchmark are mutually exclusive")
    standalone_benchmark = certificate_gen or kem_benchmark
    cmake_args = [
        f"-DBENCH_MLKEM_BACKEND={mlkem_backend}",
        f"-DBENCH_POWER_MARKERS={'ON' if power_markers else 'OFF'}",
        f"-DBENCH_BLE_TELEMETRY={'ON' if ble_telemetry else 'OFF'}",
        f"-DBENCH_MTLS_MODE={'ON' if mtls_mode else 'OFF'}",
        f"-DBENCH_CERTIFICATE_GEN={'ON' if certificate_gen else 'OFF'}",
        f"-DBENCH_KEM_OPERATIONS={'ON' if kem_benchmark else 'OFF'}",
        f"-DBENCH_TRANSFER_MODE={'ON' if transfer_mode else 'OFF'}",
    ]
    if not standalone_benchmark:
        cmake_args.append(f"-DBENCH_GENERATED_DIR={generated_dir}")
    else:
        cmake_args.append(
            f"-DEXTRA_CONF_FILE={firmware_dir / ('kem_bench.conf' if kem_benchmark else 'certgen.conf')}"
        )
    is_nrf5340 = board.startswith("nrf5340dk/")
    if pqm4_dir is not None:
        cmake_args.append(f"-DPQM4_ROOT={pqm4_dir}")
    build_env = toolchain_environment(nrfutil)
    if not standalone_benchmark:
        build_env["BENCH_GENERATED_DIR"] = str(generated_dir)
    build_env["BENCH_MLKEM_BACKEND"] = mlkem_backend
    build_env["BENCH_MTLS_MODE"] = "ON" if mtls_mode else "OFF"
    build_env["BENCH_TRANSFER_MODE"] = "ON" if transfer_mode else "OFF"
    if pqm4_dir is not None:
        build_env["PQM4_ROOT"] = str(pqm4_dir)
    command, cwd, env = west_command(
        nrfutil=nrfutil,
        ncs_version=ncs_version,
        ncs_chdir=ncs_chdir,
        west_args=[
            "build",
            "-d", str(build_dir),
            "-p", "always",
            "--sysbuild" if is_nrf5340 and not standalone_benchmark else "--no-sysbuild",
            "-b", board,
            str(firmware_dir),
            "--", *cmake_args,
        ],
    )
    if env is None:
        env = build_env
    else:
        env.update(build_env)
    run_logged(command, log, cwd=cwd, env=env)


def flash(
    *,
    build_dir: Path,
    log: Path,
    nrfutil: str,
    ncs_version: str,
    ncs_chdir: str,
) -> None:
    command, cwd, env = west_command(
        nrfutil=nrfutil,
        ncs_version=ncs_version,
        ncs_chdir=ncs_chdir,
        west_args=["flash", "-d", str(build_dir), "--runner", "nrfutil"],
    )
    run_logged(command, log, cwd=cwd, env=env)


def flash_usage(build_dir: Path) -> tuple[int, int]:
    """Read the linked image footprint and FLASH capacity from Zephyr's map."""
    map_paths = (
        build_dir / "zephyr" / "zephyr.map",
        build_dir / "firmware" / "zephyr" / "zephyr.map",
    )
    map_path = next((path for path in map_paths if path.exists()), map_paths[0])
    text = map_path.read_text(errors="replace")
    used_match = re.search(r"0x([0-9a-fA-F]+)\s+_flash_used\s*=", text)
    region_match = re.search(
        r"^FLASH\s+0x[0-9a-fA-F]+\s+0x([0-9a-fA-F]+)\s+", text,
        re.MULTILINE,
    )
    if used_match is None or region_match is None:
        raise ValueError(f"cannot parse FLASH usage from {map_path}")
    return int(used_match.group(1), 16), int(region_match.group(1), 16)


def reset(*, log: Path, nrfutil: str) -> None:
    """Reset the attached DK after its measured VDD rail is restored."""
    run_logged(
        [nrfutil, "device", "reset", "--traits", "jlink"],
        log,
        env=toolchain_environment(nrfutil),
    )
