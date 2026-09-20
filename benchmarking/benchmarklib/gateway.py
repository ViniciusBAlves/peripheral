from __future__ import annotations

import os
import json
import shlex
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path


class PiGateway:
    def __init__(self, host: str, workdir: str, ssh_key: str = "") -> None:
        self.host = host
        self.workdir = workdir
        self.ssh_key = ssh_key
        self.control_path = f"/tmp/peripheral-bench-ssh-{os.getpid()}"
        self.ble_addr = ""

    def ssh_base(self) -> list[str]:
        command = [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "ControlMaster=auto",
            "-o", "ControlPersist=10m", "-o", f"ControlPath={self.control_path}",
        ]
        if self.ssh_key:
            command.extend(["-i", self.ssh_key])
        return command

    def start_master(
        self, log: Path, *, attempts: int = 6, retry_delay: float = 5.0
    ) -> None:
        command = [*self.ssh_base(), "-MNf", self.host]
        for attempt in range(1, attempts + 1):
            try:
                self._local(command, log)
                return
            except RuntimeError:
                Path(self.control_path).unlink(missing_ok=True)
                if attempt == attempts:
                    raise
                with log.open("a") as stream:
                    stream.write(
                        f"[ssh] master connection attempt {attempt}/{attempts} "
                        f"failed; retrying in {retry_delay:g}s\n"
                    )
                time.sleep(retry_delay)

    def stop_master(self) -> None:
        subprocess.run([*self.ssh_base(), "-O", "exit", self.host], capture_output=True)

    def set_wifi_enabled(self, enabled: bool, log: Path) -> None:
        """Keep the Pi radio state stable across all benchmark sessions."""
        state = "on" if enabled else "off"
        link_state = "up" if enabled else "down"
        self.command(
            f"sudo -n nmcli radio wifi {state} >/dev/null 2>&1 || "
            f"sudo -n ip link set wlan0 {link_state} >/dev/null 2>&1 || true",
            log,
            check=False,
        )

    def _local(self, command: list[str], log: Path) -> None:
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("a") as stream:
            stream.write(f"$ {' '.join(command)}\n")
            proc = subprocess.run(command, text=True, stdout=stream, stderr=subprocess.STDOUT)
        if proc.returncode:
            detail = log.read_text(errors="replace").strip()
            if len(detail) > 2000:
                detail = detail[-2000:]
            raise RuntimeError(
                "local command failed with exit "
                f"{proc.returncode}: {' '.join(command)}\n{detail}"
            )

    def command(self, script: str, log: Path, *, check: bool = True) -> subprocess.CompletedProcess[str]:
        command = [*self.ssh_base(), self.host, f"bash -lc {shlex.quote(script)}"]
        log.parent.mkdir(parents=True, exist_ok=True)
        with log.open("a") as stream:
            stream.write(f"$ remote: {script}\n")
            proc = subprocess.run(command, text=True, stdout=stream, stderr=subprocess.STDOUT)
        if check and proc.returncode:
            raise subprocess.CalledProcessError(proc.returncode, command)
        return proc

    def remote_file_contains(self, path: str, patterns: tuple[str, ...]) -> str:
        if not patterns:
            return ""
        regex = "|".join(patterns)
        script = (
            f"test -f {shlex.quote(path)} && "
            f"grep -Eim1 -- {shlex.quote(regex)} {shlex.quote(path)}"
        )
        command = [*self.ssh_base(), self.host, f"bash -lc {shlex.quote(script)}"]
        proc = subprocess.run(
            command, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        if proc.returncode == 0:
            return proc.stdout.strip().splitlines()[0]
        return ""

    def remote_benchmark_result(self, case_id: str) -> str:
        path = f"{self.workdir}/logs/{case_id}.gateway.log"
        script = (
            f"test -f {shlex.quote(path)} && "
            f"grep '^\\[BENCH_RESULT\\]' {shlex.quote(path)} | tail -n 1"
        )
        command = [*self.ssh_base(), self.host, f"bash -lc {shlex.quote(script)}"]
        proc = subprocess.run(
            command, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        return proc.stdout.strip() if proc.returncode == 0 else ""

    def remote_bridge_failure(self, case_id: str) -> str:
        """Return a terminal bridge error instead of waiting for the round deadline."""
        path = f"{self.workdir}/logs/{case_id}.gateway.log"
        regex = "|".join((
            r"L2CAP send failed", r"L2CAP receive failed",
            r"TCP send failed", r"TCP receive failed",
        ))
        script = (
            f"if test -f {shlex.quote(path)} && "
            f"failure=$(grep -Eim1 -- {shlex.quote(regex)} {shlex.quote(path)}); "
            "then printf '%s\\n' \"$failure\"; "
            f"else pid=$(cat {self.workdir}/bridge.pid 2>/dev/null || true); "
            "[ -n \"$pid\" ] && kill -0 \"$pid\" 2>/dev/null || "
            "printf '%s\\n' 'bridge process exited'; fi"
        )
        command = [*self.ssh_base(), self.host, f"bash -lc {shlex.quote(script)}"]
        proc = subprocess.run(
            command, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        return proc.stdout.strip().splitlines()[0] if proc.stdout.strip() else ""

    def deploy_file(self, source: Path, destination: str, log: Path) -> None:
        ssh_transport = " ".join(shlex.quote(part) for part in self.ssh_base())
        self._local(
            ["rsync", "-a", "-e", ssh_transport, str(source), f"{self.host}:{destination}"],
            log,
        )

    def prepare(
        self,
        bridge_source: Path,
        wolfssl_server_source: Path,
        log: Path,
        wolfssl_source_dir: Path | None = None,
    ) -> None:
        self.command(f"mkdir -p {shlex.quote(self.workdir)}/{{bin,cases,logs,deps}}", log)
        self.deploy_file(bridge_source, f"{self.workdir}/bin/ble_mqtt_bridge.c", log)
        self.deploy_file(
            bridge_source.parent / "server_crypto_metrics.c",
            f"{self.workdir}/bin/server_crypto_metrics.c",
            log,
        )
        transfer_controller = bridge_source.parent / "mqtt_transfer_controller.py"
        if transfer_controller.exists():
            self.deploy_file(
                transfer_controller,
                f"{self.workdir}/bin/mqtt_transfer_controller.py",
                log,
            )
        self.deploy_file(
            wolfssl_server_source,
            f"{self.workdir}/bin/wolfssl_tls_server.c",
            log,
        )
        self.deploy_file(
            wolfssl_server_source.parent / "setup_pi_wolfssl.sh",
            f"{self.workdir}/bin/setup_pi_wolfssl.sh",
            log,
        )
        if wolfssl_source_dir is not None and wolfssl_source_dir.exists():
            remote_archive = f"{self.workdir}/deps/wolfssl/wolfssl-clean-source.tar.gz"
            if wolfssl_source_dir.is_file():
                self.deploy_file(wolfssl_source_dir, remote_archive, log)
            else:
                with tempfile.NamedTemporaryFile(suffix=".tar.gz") as archive:
                    with tarfile.open(archive.name, "w:gz") as tar:
                        tar.add(wolfssl_source_dir, arcname="src")
                    self.deploy_file(Path(archive.name), remote_archive, log)
        self.command(
            f"cd {shlex.quote(self.workdir)} && "
            "gcc -O2 -Wall -Wextra -o bin/ble_mqtt_bridge "
            "bin/ble_mqtt_bridge.c $(pkg-config --cflags --libs bluez) && "
            "gcc -O2 -Wall -Wextra -shared -fPIC "
            "-o bin/server_crypto_metrics.so bin/server_crypto_metrics.c "
            "-ldl -lcrypto",
            log,
        )
        # Capabilities let the bridge open Bluetooth sockets without leaving a
        # long-lived sudo wrapper that the runner cannot reliably terminate.
        self.command(
            f"sudo -n /usr/sbin/setcap cap_net_admin,cap_net_raw+eip "
            f"{shlex.quote(self.workdir)}/bin/ble_mqtt_bridge",
            log,
        )
        self.command(
            "OPENSSL_CONF=/dev/null OPENSSL_MODULES=/usr/local/lib/ossl-modules "
            "openssl list -providers -provider default -provider oqsprovider "
            "| grep -q oqsprovider",
            log,
        )
        self.command(
            f"cd {shlex.quote(self.workdir)} && "
            "chmod +x bin/setup_pi_wolfssl.sh && "
            "./bin/setup_pi_wolfssl.sh deps/wolfssl && "
            "export PKG_CONFIG_PATH=\"$PWD/deps/wolfssl/lib/pkgconfig\" && "
            "pkg-config --exists wolfssl && "
            "gcc -O2 -Wall -Wextra -DWOLFSSL_HAVE_XMSS "
            "  -o bin/wolfssl_tls_server bin/wolfssl_tls_server.c "
            "  $(pkg-config --cflags --libs wolfssl) "
            "  -Wl,-rpath,\"$PWD/deps/wolfssl/lib\" && "
            "test -x bin/wolfssl_tls_server",
            log,
        )

    def deploy_case(self, case_id: str, directory: Path, log: Path) -> str:
        remote = f"{self.workdir}/cases/{case_id}"
        self.command(f"rm -rf {shlex.quote(remote)} && mkdir -p {shlex.quote(remote)}", log)
        ssh_transport = " ".join(shlex.quote(part) for part in self.ssh_base())
        self._local(
            ["rsync", "-a", "-e", ssh_transport, f"{directory}/", f"{self.host}:{remote}/"],
            log,
        )
        self.command(
            f"sed -i 's|__REMOTE_CASE_DIR__|{remote}|g' "
            f"{remote}/mosquitto.conf; "
            f"for config in {remote}/mosquitto*.conf; do "
            f"  [ ! -f \"$config\" ] || "
            f"  sed -i 's|__REMOTE_CASE_DIR__|{remote}|g' \"$config\"; "
            f"done",
            log,
        )
        return remote

    def stop_session(self, log: Path, *, reset_adapter: bool = False) -> None:
        bridge_pattern = f"^{self.workdir}/bin/ble_mqtt_bridge( |$)"
        broker_pattern = f"^/usr/sbin/mosquitto -c {self.workdir}/cases/"
        wolfssl_pattern = f"^{self.workdir}/bin/wolfssl_tls_server( |$)"
        controller_pattern = f"^python3 {self.workdir}/bin/mqtt_transfer_controller.py( |$)"
        reset_command = ""
        disconnect_command = ""
        if self.ble_addr:
            disconnect_command = (
                "timeout -k 1 5 bluetoothctl disconnect "
                f"{shlex.quote(self.ble_addr)} >/dev/null 2>&1 || true; "
                "sleep 0.5; "
            )
        if reset_adapter:
            reset_command = (
                "sudo -n /usr/sbin/rfkill block bluetooth "
                ">/dev/null 2>&1 || true; sleep 1; "
                "sudo -n /usr/sbin/rfkill unblock bluetooth "
                ">/dev/null 2>&1 || true; sleep 2; "
                "sudo -n timeout -k 1 4 /usr/bin/btmgmt power off "
                ">/dev/null 2>&1 || true; sleep 1; "
                "sudo -n timeout -k 1 4 /usr/bin/btmgmt bredr off "
                ">/dev/null 2>&1 || true; "
                "sudo -n timeout -k 1 4 /usr/bin/btmgmt bondable off "
                ">/dev/null 2>&1 || true; "
                "sudo -n timeout -k 1 4 /usr/bin/btmgmt sc off "
                ">/dev/null 2>&1 || true; "
                "sudo -n timeout -k 1 4 /usr/bin/btmgmt privacy off "
                ">/dev/null 2>&1 || true; "
                "sudo -n timeout -k 1 4 /usr/bin/btmgmt power on "
                ">/dev/null 2>&1 || true; sleep 1; "
            )
        self.command(
            f"if [ -f {self.workdir}/bridge.pid ]; then "
            f"  pid=$(cat {self.workdir}/bridge.pid); "
            "  kill -TERM -- \"-$pid\" \"$pid\" 2>/dev/null || true; "
            "  sleep 0.2; "
            "  kill -KILL -- \"-$pid\" \"$pid\" 2>/dev/null || true; "
            f"  rm -f {self.workdir}/bridge.pid; "
            "fi; "
            f"if [ -f {self.workdir}/broker.pid ]; then "
            f"  pid=$(cat {self.workdir}/broker.pid); "
            "  kill -TERM -- \"-$pid\" \"$pid\" 2>/dev/null || true; "
            "  sleep 0.2; "
            "  kill -KILL -- \"-$pid\" \"$pid\" 2>/dev/null || true; "
            f"  rm -f {self.workdir}/broker.pid; "
            "fi; "
            f"if [ -f {self.workdir}/controller.pid ]; then "
            f"  pid=$(cat {self.workdir}/controller.pid); "
            "  kill -TERM -- \"-$pid\" \"$pid\" 2>/dev/null || true; "
            "  sleep 0.2; "
            "  kill -KILL -- \"-$pid\" \"$pid\" 2>/dev/null || true; "
            f"  rm -f {self.workdir}/controller.pid; "
            "fi; "
            f"pids=$(pgrep -f {shlex.quote(bridge_pattern)} || true); "
            "  [ -z \"$pids\" ] || kill -KILL $pids 2>/dev/null || "
            "    sudo -n kill -KILL $pids 2>/dev/null || true; "
            f"pids=$(pgrep -f {shlex.quote(broker_pattern)} || true); "
            "  [ -z \"$pids\" ] || kill -KILL $pids 2>/dev/null || true; "
            f"pids=$(pgrep -f {shlex.quote(wolfssl_pattern)} || true); "
            "  [ -z \"$pids\" ] || kill -KILL $pids 2>/dev/null || true; "
            f"pids=$(pgrep -f {shlex.quote(controller_pattern)} || true); "
            "  [ -z \"$pids\" ] || kill -KILL $pids 2>/dev/null || true; "
            f"{disconnect_command}"
            f"{reset_command}",
            log,
            check=False,
        )

    def start_session(
        self,
        *,
        case_id: str,
        remote_case_dir: str,
        ble_addr: str,
        ble_name: str,
        ble_addr_type: str,
        psm: str,
        mtu: int,
        adapter: str,
        disable_wifi: bool,
        ready_timeout: float,
        log: Path,
        server_backend: str = "openssl-mosquitto",
        wolfssl_group: str = "",
        control_telemetry: bool = False,
        root_signature: str = "",
        leaf_signature: str = "",
        signature_scheme: str = "",
        tls_timeout_sec: float = 60.0,
        mtls_mode: bool = False,
        transfer_plan: dict[str, object] | None = None,
    ) -> None:
        self.stop_session(log, reset_adapter=False)
        self.ble_addr = ble_addr
        supervision_timeout_path = (
            f"/sys/kernel/debug/bluetooth/{adapter}/supervision_timeout"
        )
        self.command(
            "printf '3200\\n' | sudo -n /usr/bin/tee "
            f"{shlex.quote(supervision_timeout_path)} >/dev/null",
            log,
        )
        broker_log = f"{self.workdir}/logs/{case_id}.broker.log"
        controller_log = f"{self.workdir}/logs/{case_id}.transfer-server.log"
        gateway_log = f"{self.workdir}/logs/{case_id}.gateway.log"
        transfer_json = f"{self.workdir}/logs/{case_id}.transfer.json"
        transfer_csv = f"{self.workdir}/logs/{case_id}.transfer.csv"
        if transfer_plan is not None:
            operations = transfer_plan.get("operations", [])
            csv_text = "order,direction,size,seed\n" + "".join(
                f"{operation['order']},{operation['direction']},"
                f"{operation['payload_bytes']},{operation['payload_seed']}\n"
                for operation in operations
            )
            self.command(
                f"printf '%s' {shlex.quote(json.dumps(transfer_plan))} > "
                f"{shlex.quote(transfer_json)}; "
                f"printf '%s' {shlex.quote(csv_text)} > {shlex.quote(transfer_csv)}",
                log,
            )
        address = f"--addr {shlex.quote(ble_addr)}" if ble_addr else ""
        bridge_command = (
            f"setsid {shlex.quote(self.workdir)}/bin/ble_mqtt_bridge "
            f"--adapter {shlex.quote(adapter)} --name {shlex.quote(ble_name)} "
            f"{address} --addr-type {shlex.quote(ble_addr_type)} "
            f"--psm {shlex.quote(psm)} --tcp-host 127.0.0.1 --tcp-port 8883 "
            f"--mtu {mtu} --scan-timeout 5 "
            f"--root-signature {shlex.quote(root_signature)} "
            f"--leaf-signature {shlex.quote(leaf_signature)} "
            f"> {gateway_log} 2>&1 < /dev/null & "
            f"echo $! > {self.workdir}/bridge.pid"
        )
        if server_backend == "wolfssl":
            if not wolfssl_group:
                raise ValueError("wolfssl_group is required for wolfssl backend")
            server_command = (
                f"setsid {shlex.quote(self.workdir)}/bin/wolfssl_tls_server "
                f"--case-dir {remote_case_dir} "
                f"--group {shlex.quote(wolfssl_group)} --port 8883 "
                f"--sigalg {shlex.quote(signature_scheme)} "
                f"--timeout {max(1, int(tls_timeout_sec))} "
                f"{'--mtls ' if mtls_mode else ''}"
                f"{'--transfer-plan ' + shlex.quote(transfer_csv) + ' ' if transfer_plan else ''}"
                f"> {broker_log} 2>&1 < /dev/null & "
                f"echo $! > {self.workdir}/broker.pid"
            )
        else:
            if transfer_plan is not None:
                mosquitto_config = (
                    "mosquitto-transfer-mtls.conf" if mtls_mode
                    else "mosquitto-transfer.conf"
                )
            else:
                mosquitto_config = (
                    "mosquitto-mtls.conf" if mtls_mode else "mosquitto.conf"
                )
            server_command = (
                f"setsid env OPENSSL_CONF={remote_case_dir}/"
                f"{'openssl-mtls.cnf' if mtls_mode else 'openssl.cnf'} "
                f"/usr/sbin/mosquitto -c "
                f"{remote_case_dir}/"
                f"{mosquitto_config} -v "
                f"> {broker_log} 2>&1 < /dev/null & "
                f"echo $! > {self.workdir}/broker.pid"
            )
        controller_command = ""
        if transfer_plan is not None and server_backend != "wolfssl":
            controller_command = (
                f"setsid python3 {self.workdir}/bin/mqtt_transfer_controller.py "
                f"--plan {shlex.quote(transfer_json)} "
                "--port 18884 "
                f"--timeout {max(30, min(90, int(tls_timeout_sec)))} "
                f"> {controller_log} 2>&1 < /dev/null & "
                f"echo $! > {self.workdir}/controller.pid; "
            )
        script = (
            f": > {broker_log}; : > {gateway_log}; : > {controller_log}; "
            f"LD_PRELOAD={self.workdir}/bin/server_crypto_metrics.so "
            f"{server_command}; "
            "sleep 1; "
            f"if kill -0 $(cat {self.workdir}/broker.pid) 2>/dev/null; then "
            f"{controller_command}"
            f"{bridge_command}; "
            "else exit 1; fi"
        )
        self.command(script, log)
        checks = max(1, int(ready_timeout * 4))
        ready_check = (
            f"grep -q '^\\[BENCH_READY\\].*transport=l2cap' {gateway_log} && "
            if control_telemetry else ""
        )
        self.command(
            f"for i in $(seq 1 {checks}); do "
            f"  {ready_check}"
            f"grep -q '\\[BENCH_GATEWAY\\] gateway_tcp_connect_ms=' {gateway_log} "
            "    && exit 0; "
            f"  pid=$(cat {self.workdir}/bridge.pid 2>/dev/null || true); "
            "  [ -n \"$pid\" ] && kill -0 \"$pid\" 2>/dev/null || exit 1; "
            "  sleep 0.25; "
            "done; exit 1",
            log,
        )

    def collect_session_logs(
        self,
        case_id: str,
        broker_log: Path,
        gateway_log: Path,
        log: Path,
    ) -> None:
        remote_broker = f"{self.workdir}/logs/{case_id}.broker.log"
        remote_controller = f"{self.workdir}/logs/{case_id}.transfer-server.log"
        remote_gateway = f"{self.workdir}/logs/{case_id}.gateway.log"
        for remote, local in (
            (remote_broker, broker_log),
            (remote_controller, broker_log),
            (remote_gateway, gateway_log),
        ):
            command = [*self.ssh_base(), self.host, f"cat {shlex.quote(remote)}"]
            local.parent.mkdir(parents=True, exist_ok=True)
            with local.open("a") as stream:
                subprocess.run(command, text=True, stdout=stream, stderr=subprocess.STDOUT)
