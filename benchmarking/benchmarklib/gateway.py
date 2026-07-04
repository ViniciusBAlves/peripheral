from __future__ import annotations

import os
import shlex
import subprocess
from pathlib import Path


class PiGateway:
    def __init__(self, host: str, workdir: str, ssh_key: str = "") -> None:
        self.host = host
        self.workdir = workdir
        self.ssh_key = ssh_key
        self.control_path = f"/tmp/peripheral-bench-ssh-{os.getpid()}"

    def ssh_base(self) -> list[str]:
        command = [
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
            "-o", "ControlMaster=auto",
            "-o", "ControlPersist=10m", "-o", f"ControlPath={self.control_path}",
        ]
        if self.ssh_key:
            command.extend(["-i", self.ssh_key])
        return command

    def start_master(self, log: Path) -> None:
        command = [*self.ssh_base(), "-MNf", self.host]
        self._local(command, log)

    def stop_master(self) -> None:
        subprocess.run([*self.ssh_base(), "-O", "exit", self.host], capture_output=True)

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

    def deploy_file(self, source: Path, destination: str, log: Path) -> None:
        ssh_transport = " ".join(shlex.quote(part) for part in self.ssh_base())
        self._local(
            ["rsync", "-a", "-e", ssh_transport, str(source), f"{self.host}:{destination}"],
            log,
        )

    def prepare(self, bridge_source: Path, wolfssl_server_source: Path, log: Path) -> None:
        self.command(f"mkdir -p {shlex.quote(self.workdir)}/{{bin,cases,logs}}", log)
        self.deploy_file(bridge_source, f"{self.workdir}/bin/ble_mqtt_bridge.c", log)
        self.deploy_file(
            bridge_source.parent / "server_crypto_metrics.c",
            f"{self.workdir}/bin/server_crypto_metrics.c",
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
            f"sed -i 's|__REMOTE_CASE_DIR__|{remote}|g' {remote}/mosquitto.conf",
            log,
        )
        return remote

    def stop_session(self, log: Path, *, reset_adapter: bool = False) -> None:
        bridge_pattern = f"^{self.workdir}/bin/ble_mqtt_bridge( |$)"
        broker_pattern = f"^/usr/sbin/mosquitto -c {self.workdir}/cases/"
        wolfssl_pattern = f"^{self.workdir}/bin/wolfssl_tls_server( |$)"
        reset_command = ""
        if reset_adapter:
            reset_command = (
                "sudo -n /usr/sbin/rfkill block wifi >/dev/null 2>&1 || true; "
                "sudo -n /usr/bin/nmcli radio wifi off >/dev/null 2>&1 || true; "
                "sudo -n /usr/sbin/ip link set wlan0 down >/dev/null 2>&1 || true; "
                "sleep 1; "
                "sudo -n timeout -k 1 4 /usr/bin/btmgmt power off "
                ">/dev/null 2>&1 || true; sleep 1; "
                "sudo -n timeout -k 1 4 /usr/bin/btmgmt power on "
                ">/dev/null 2>&1 || true; sleep 1; "
                "sudo -n timeout -k 1 4 /usr/bin/btmgmt bredr off "
                ">/dev/null 2>&1 || true; "
                "sudo -n timeout -k 1 4 /usr/bin/btmgmt bondable off "
                ">/dev/null 2>&1 || true; "
                "sudo -n timeout -k 1 4 /usr/bin/btmgmt sc off "
                ">/dev/null 2>&1 || true; "
                "sudo -n timeout -k 1 4 /usr/bin/btmgmt privacy off "
                ">/dev/null 2>&1 || true; "
                "sudo -n /usr/sbin/rfkill unblock wifi >/dev/null 2>&1 || true; "
                "sudo -n /usr/bin/nmcli radio wifi on >/dev/null 2>&1 || true; "
                "sudo -n /usr/sbin/ip link set wlan0 up >/dev/null 2>&1 || true; "
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
            f"pids=$(pgrep -f {shlex.quote(bridge_pattern)} || true); "
            "  [ -z \"$pids\" ] || kill -KILL $pids 2>/dev/null || "
            "    sudo -n kill -KILL $pids 2>/dev/null || true; "
            f"pids=$(pgrep -f {shlex.quote(broker_pattern)} || true); "
            "  [ -z \"$pids\" ] || kill -KILL $pids 2>/dev/null || true; "
            f"pids=$(pgrep -f {shlex.quote(wolfssl_pattern)} || true); "
            "  [ -z \"$pids\" ] || kill -KILL $pids 2>/dev/null || true; "
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
    ) -> None:
        self.stop_session(log, reset_adapter=disable_wifi)
        broker_log = f"{self.workdir}/logs/{case_id}.broker.log"
        gateway_log = f"{self.workdir}/logs/{case_id}.gateway.log"
        address = f"--addr {shlex.quote(ble_addr)}" if ble_addr else ""
        bridge_command = (
            f"setsid {shlex.quote(self.workdir)}/bin/ble_mqtt_bridge "
            f"--adapter {shlex.quote(adapter)} --name {shlex.quote(ble_name)} "
            f"{address} --addr-type {shlex.quote(ble_addr_type)} "
            f"--psm {shlex.quote(psm)} --tcp-host 127.0.0.1 --tcp-port 8883 "
            f"--mtu {mtu} --scan-timeout 5 --no-acl-prime "
            f"{'--disable-wifi ' if disable_wifi else ''}"
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
                f"> {broker_log} 2>&1 < /dev/null & "
                f"echo $! > {self.workdir}/broker.pid"
            )
        else:
            server_command = (
                f"setsid env OPENSSL_CONF={remote_case_dir}/openssl.cnf "
                f"/usr/sbin/mosquitto -c {remote_case_dir}/mosquitto.conf -v "
                f"> {broker_log} 2>&1 < /dev/null & "
                f"echo $! > {self.workdir}/broker.pid"
            )
        script = (
            f": > {broker_log}; : > {gateway_log}; "
            f"LD_PRELOAD={self.workdir}/bin/server_crypto_metrics.so "
            f"{server_command}; "
            "sleep 1; "
            f"kill -0 $(cat {self.workdir}/broker.pid) 2>/dev/null; "
            f"{bridge_command}"
        )
        self.command(script, log)
        checks = max(1, int(ready_timeout * 4))
        self.command(
            f"for i in $(seq 1 {checks}); do "
            f"  grep -q '\\[BENCH_GATEWAY\\] gateway_tcp_connect_ms=' {gateway_log} "
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
        remote_gateway = f"{self.workdir}/logs/{case_id}.gateway.log"
        for remote, local in ((remote_broker, broker_log), (remote_gateway, gateway_log)):
            command = [*self.ssh_base(), self.host, f"cat {shlex.quote(remote)}"]
            local.parent.mkdir(parents=True, exist_ok=True)
            with local.open("a") as stream:
                subprocess.run(command, text=True, stdout=stream, stderr=subprocess.STDOUT)
