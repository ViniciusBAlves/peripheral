from __future__ import annotations

import subprocess
from pathlib import Path


def run_logged(command: list[str], log: Path) -> None:
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a") as stream:
        stream.write(f"$ {' '.join(command)}\n")
        proc = subprocess.run(command, text=True, stdout=stream, stderr=subprocess.STDOUT)
    if proc.returncode:
        raise subprocess.CalledProcessError(proc.returncode, command)


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
) -> None:
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
            "--", f"-DBENCH_GENERATED_DIR={generated_dir}",
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
