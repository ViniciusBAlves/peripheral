from __future__ import annotations

import os
import shlex
import subprocess
import tarfile
import tempfile
from pathlib import Path


class PiGateway:
    def __init__(self, host: str, workdir: str, ssh_key: str = "") -> None:
        self.host = host
        self.workdir = workdir
        self.ssh_key = ssh_key
        self.control_path = f"/tmp/peripheral-bench-ssh-{os.getpid()}"
        self.ble_addr = ""
        self.active_case_id = ""

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
        self.deploy_file(
            bridge_source.parent / "pi_perf_counter.c",
            f"{self.workdir}/bin/pi_perf_counter.c",
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
        self.deploy_file(
            wolfssl_server_source.parent / "setup_pi_mosquitto.sh",
            f"{self.workdir}/bin/setup_pi_mosquitto.sh",
            log,
        )
        self.deploy_file(
            wolfssl_server_source.parent / "pi_perf_metrics.sh",
            f"{self.workdir}/bin/pi_perf_metrics.sh",
            log,
        )
        mosquitto_archive = (
            wolfssl_server_source.parent.parent
            / "work"
            / "mosquitto-2.0.21-source.tar.gz"
        )
        if mosquitto_archive.exists():
            self.deploy_file(
                mosquitto_archive,
                f"{self.workdir}/deps/mosquitto-source.tar.gz",
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
            "gcc -O2 -Wall -Wextra -o bin/pi_perf_counter "
            "bin/pi_perf_counter.c && "
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
            "chmod +x bin/pi_perf_metrics.sh && "
            "./bin/pi_perf_metrics.sh setup \"$PWD\" && "
            "cat logs/pi_hardware.log && "
            "chmod +x bin/setup_pi_mosquitto.sh && "
            "./bin/setup_pi_mosquitto.sh deps/mosquitto "
            "deps/mosquitto-source.tar.gz && "
            "test -x deps/mosquitto/bin/mosquitto",
            log,
        )
        self.command(
            f"cd {shlex.quote(self.workdir)} && "
            "chmod +x bin/setup_pi_wolfssl.sh && "
            "./bin/setup_pi_wolfssl.sh deps/wolfssl && "
            "export PKG_CONFIG_PATH=\"$PWD/deps/wolfssl/lib/pkgconfig\" && "
            "pkg-config --exists wolfssl && "
            "gcc -O2 -Wall -Wextra "
            "-DWOLFSSL_HAVE_LMS -DWOLFSSL_HAVE_XMSS "
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
        metrics_command = ""
        if self.active_case_id:
            broker_log = f"{self.workdir}/logs/{self.active_case_id}.broker.log"
            gateway_log = f"{self.workdir}/logs/{self.active_case_id}.gateway.log"
            metrics_command = (
                f"{shlex.quote(self.workdir)}/bin/pi_perf_metrics.sh stop "
                f"{shlex.quote(self.workdir)} {shlex.quote(self.active_case_id)} "
                "pi_broker; "
                f"{shlex.quote(self.workdir)}/bin/pi_perf_metrics.sh stop "
                f"{shlex.quote(self.workdir)} {shlex.quote(self.active_case_id)} "
                "pi_bridge; "
                "collect_proc_metrics() { "
                "pid=\"$1\"; out=\"$2\"; tag=\"$3\"; prefix=\"$4\"; "
                "[ -n \"$pid\" ] && [ -r \"/proc/$pid/stat\" ] || return 0; "
                "stat_line=$(cat \"/proc/$pid/stat\" 2>/dev/null || true); "
                "status_file=\"/proc/$pid/status\"; io_file=\"/proc/$pid/io\"; "
                "minflt=$(printf '%s\\n' \"$stat_line\" | awk '{print $10}'); "
                "majflt=$(printf '%s\\n' \"$stat_line\" | awk '{print $12}'); "
                "utime=$(printf '%s\\n' \"$stat_line\" | awk '{print $14}'); "
                "stime=$(printf '%s\\n' \"$stat_line\" | awk '{print $15}'); "
                "threads=$(printf '%s\\n' \"$stat_line\" | awk '{print $20}'); "
                "vmrss=$(awk '/^VmRSS:/ {print $2}' \"$status_file\" 2>/dev/null || true); "
                "vmhwm=$(awk '/^VmHWM:/ {print $2}' \"$status_file\" 2>/dev/null || true); "
                "vol=$(awk '/^voluntary_ctxt_switches:/ {print $2}' \"$status_file\" 2>/dev/null || true); "
                "invol=$(awk '/^nonvoluntary_ctxt_switches:/ {print $2}' \"$status_file\" 2>/dev/null || true); "
                "read_bytes=$(awk '/^read_bytes:/ {print $2}' \"$io_file\" 2>/dev/null || true); "
                "write_bytes=$(awk '/^write_bytes:/ {print $2}' \"$io_file\" 2>/dev/null || true); "
                "printf '[BENCH_%s] %s_utime_ticks=%s %s_stime_ticks=%s "
                "%s_minor_page_faults=%s %s_major_page_faults=%s "
                "%s_threads=%s %s_vmrss_kb=%s %s_vmhwm_kb=%s "
                "%s_voluntary_context_switches=%s "
                "%s_involuntary_context_switches=%s "
                "%s_read_bytes=%s %s_write_bytes=%s\\n' "
                "\"$tag\" \"$prefix\" \"$utime\" \"$prefix\" \"$stime\" "
                "\"$prefix\" \"$minflt\" \"$prefix\" \"$majflt\" "
                "\"$prefix\" \"$threads\" \"$prefix\" \"$vmrss\" "
                "\"$prefix\" \"$vmhwm\" \"$prefix\" \"$vol\" "
                "\"$prefix\" \"$invol\" \"$prefix\" \"$read_bytes\" "
                "\"$prefix\" \"$write_bytes\" >> \"$out\"; "
                "}; "
                f"broker_pid=$(cat {self.workdir}/broker.pid 2>/dev/null || true); "
                f"bridge_pid=$(cat {self.workdir}/bridge.pid 2>/dev/null || true); "
                f"collect_proc_metrics \"$broker_pid\" {shlex.quote(broker_log)} SERVER pi_broker; "
                f"collect_proc_metrics \"$bridge_pid\" {shlex.quote(gateway_log)} GATEWAY pi_bridge; "
            )
        bridge_pattern = f"^{self.workdir}/bin/ble_mqtt_bridge( |$)"
        broker_pattern = f"^/usr/sbin/mosquitto -c {self.workdir}/cases/"
        benchmark_mosquitto_pattern = (
            f"^{self.workdir}/deps/mosquitto/bin/mosquitto "
            f"-c {self.workdir}/cases/"
        )
        wolfssl_pattern = f"^{self.workdir}/bin/wolfssl_tls_server( |$)"
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
            f"{metrics_command}"
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
            f"pids=$(pgrep -f {shlex.quote(benchmark_mosquitto_pattern)} || true); "
            "  [ -z \"$pids\" ] || kill -KILL $pids 2>/dev/null || true; "
            f"pids=$(pgrep -f {shlex.quote(wolfssl_pattern)} || true); "
            "  [ -z \"$pids\" ] || kill -KILL $pids 2>/dev/null || true; "
            f"{disconnect_command}"
            f"{reset_command}",
            log,
            check=False,
        )
        self.active_case_id = ""

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
        self.ble_addr = ble_addr
        self.active_case_id = case_id
        supervision_timeout_path = (
            f"/sys/kernel/debug/bluetooth/{adapter}/supervision_timeout"
        )
        self.command(
            "printf '3200\\n' | sudo -n /usr/bin/tee "
            f"{shlex.quote(supervision_timeout_path)} >/dev/null",
            log,
        )
        broker_log = f"{self.workdir}/logs/{case_id}.broker.log"
        gateway_log = f"{self.workdir}/logs/{case_id}.gateway.log"
        address = f"--addr {shlex.quote(ble_addr)}" if ble_addr else ""
        bridge_command = (
            f"setsid {shlex.quote(self.workdir)}/bin/ble_mqtt_bridge "
            f"--adapter {shlex.quote(adapter)} --name {shlex.quote(ble_name)} "
            f"{address} --addr-type {shlex.quote(ble_addr_type)} "
            f"--psm {shlex.quote(psm)} --tcp-host 127.0.0.1 --tcp-port 8883 "
            f"--mtu {mtu} --scan-timeout 5 "
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
                f"{shlex.quote(self.workdir)}/deps/mosquitto/bin/mosquitto "
                f"-c {remote_case_dir}/mosquitto.conf -v "
                f"> {broker_log} 2>&1 < /dev/null & "
                f"echo $! > {self.workdir}/broker.pid"
            )
        script = (
            f": > {broker_log}; : > {gateway_log}; "
            f"LD_PRELOAD={self.workdir}/bin/server_crypto_metrics.so "
            f"{server_command}; "
            "sleep 1; "
            f"kill -0 $(cat {self.workdir}/broker.pid) 2>/dev/null || exit 1; "
            f"{bridge_command}; "
            f"{shlex.quote(self.workdir)}/bin/pi_perf_metrics.sh start "
            f"{shlex.quote(self.workdir)} {shlex.quote(case_id)} "
            f"pi_broker $(cat {self.workdir}/broker.pid); "
            f"{shlex.quote(self.workdir)}/bin/pi_perf_metrics.sh start "
            f"{shlex.quote(self.workdir)} {shlex.quote(case_id)} "
            f"pi_bridge $(cat {self.workdir}/bridge.pid)"
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
