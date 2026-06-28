from __future__ import annotations

import subprocess
from pathlib import Path

PQM4_URL = "https://github.com/mupq/pqm4.git"
PQM4_COMMIT = "cc2c1b992b602d285bd15991a566d5f17b34c1fa"


def run_logged(command: list[str], log: Path) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a") as stream:
        stream.write(f"$ {' '.join(command)}\n")
        proc = subprocess.run(command, text=True, stdout=stream, stderr=subprocess.STDOUT)
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
) -> None:
    cmake_args = [
        f"-DBENCH_GENERATED_DIR={generated_dir}",
        f"-DBENCH_MLKEM_BACKEND={mlkem_backend}",
        f"-DBENCH_LARGE_RSA={'ON' if large_rsa else 'OFF'}",
    ]
    if pqm4_dir is not None:
        cmake_args.append(f"-DPQM4_ROOT={pqm4_dir}")
    run_logged(
        [
            nrfutil, "sdk-manager", "toolchain", "launch",
            "--ncs-version", ncs_version,
            "--chdir", ncs_chdir,
            "--", "west", "build",
            "-d", str(build_dir),
            "-p", "always",
            "--no-sysbuild",
            "-b", board,
            str(firmware_dir),
            "--", *cmake_args,
        ],
        log,
    )


def flash(
    *,
    build_dir: Path,
    log: Path,
    nrfutil: str,
    ncs_version: str,
    ncs_chdir: str,
) -> None:
    run_logged(
        [
            nrfutil, "sdk-manager", "toolchain", "launch",
            "--ncs-version", ncs_version,
            "--chdir", ncs_chdir,
            "--", "west", "flash", "-d", str(build_dir), "--runner", "nrfutil",
        ],
        log,
    )
