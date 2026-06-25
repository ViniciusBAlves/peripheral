#!/usr/bin/env python3
import argparse
import ctypes
import errno
import re
import select
import socket
import subprocess
import sys
import threading
import time


AF_BLUETOOTH = getattr(socket, "AF_BLUETOOTH", 31)
BTPROTO_L2CAP = getattr(socket, "BTPROTO_L2CAP", 0)
BDADDR_PUBLIC = getattr(socket, "BDADDR_LE_PUBLIC", 1)
BDADDR_RANDOM = getattr(socket, "BDADDR_LE_RANDOM", 2)
SOL_BLUETOOTH = getattr(socket, "SOL_BLUETOOTH", 274)
BT_SECURITY = getattr(socket, "BT_SECURITY", 4)
BT_SECURITY_LOW = getattr(socket, "BT_SECURITY_LOW", 1)
BT_MODE = getattr(socket, "BT_MODE", 15)
BT_MODE_LE_FLOWCTL = getattr(socket, "BT_MODE_LE_FLOWCTL", 3)
BT_SNDMTU = getattr(socket, "BT_SNDMTU", 12)
BT_RCVMTU = getattr(socket, "BT_RCVMTU", 13)
DEFAULT_BLE_NAME = "PQC52840"
DEFAULT_PSM = 0x0080
DEFAULT_BROKER_HOST = "127.0.0.1"
DEFAULT_BROKER_PORT = 8883
DEFAULT_L2CAP_MTU = 672
DEFAULT_BLE_WRITE_CHUNK = 672


class SockaddrL2(ctypes.Structure):
    _fields_ = [
        ("family", ctypes.c_ushort),
        ("psm", ctypes.c_ushort),
        ("bdaddr", ctypes.c_ubyte * 6),
        ("cid", ctypes.c_ushort),
        ("bdaddr_type", ctypes.c_ubyte),
    ]


def run_host_cmd(cmd, timeout=None, capture=False):
    try:
        return subprocess.run(
            cmd,
            timeout=timeout,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.PIPE if capture else subprocess.DEVNULL,
            text=capture,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None


def prepare_bluetooth_adapter(addr, scan_seconds, forget_cache):
    run_host_cmd(["bluetoothctl", "power", "on"], timeout=5)
    run_host_cmd(["bluetoothctl", "disconnect", addr], timeout=5)
    if forget_cache:
        print(f"[BLE] Removing cached BlueZ record for {addr}")
        run_host_cmd(["bluetoothctl", "remove", addr], timeout=5)

    if scan_seconds <= 0:
        return

    print(f"[BLE] Scanning for {scan_seconds:.1f}s before L2CAP connect")
    run_host_cmd(["bluetoothctl", "--timeout", str(int(scan_seconds)), "scan", "on"], timeout=scan_seconds + 2)
    run_host_cmd(["bluetoothctl", "scan", "off"], timeout=5)


def establish_acl_connection(addr, retries=20):
    for attempt in range(1, retries + 1):
        print(f"[BLE] ACL connect {attempt}/{retries} through BlueZ")
        result = run_host_cmd(
            ["bluetoothctl", "--timeout", "8", "connect", addr],
            timeout=10,
            capture=True,
        )
        output = ((result.stdout or "") + (result.stderr or "")) if result else ""
        if result and (
            result.returncode == 0
            or "Connection successful" in output
            or "already connected" in output.lower()
        ):
            print("[BLE] ACL connection established")
            return
        time.sleep(0.5)
    raise OSError("BlueZ ACL connection retry limit reached")


def discover_ble_address(name, scan_seconds):
    print(f"[BLE] Looking for device named {name!r}")
    run_host_cmd(["bluetoothctl", "power", "on"], timeout=5)
    if scan_seconds > 0:
        run_host_cmd(
            ["bluetoothctl", "--timeout", str(max(1, int(scan_seconds))), "scan", "on"],
            timeout=scan_seconds + 3,
        )
        run_host_cmd(["bluetoothctl", "scan", "off"], timeout=5)

    result = run_host_cmd(["bluetoothctl", "devices"], timeout=5, capture=True)
    if result is None:
        raise OSError("bluetoothctl is not installed")

    device_pattern = re.compile(
        r"^Device\s+([0-9A-Fa-f:]{17})\s+(.+?)\s*$", re.MULTILINE
    )
    matches = [
        address.upper()
        for address, device_name in device_pattern.findall(result.stdout or "")
        if device_name == name
    ]
    if not matches:
        raise OSError(f"BLE device named {name!r} was not found")

    address = matches[-1]
    print(f"[BLE] Found {name!r} at {address}")
    return address


def read_u16_sockopt(sock, level, optname):
    try:
        raw = sock.getsockopt(level, optname, 4)
    except OSError:
        return None

    if len(raw) < 2:
        return None

    return int.from_bytes(raw[:2], "little")


def configure_l2cap_socket(sock, l2cap_mtu):
    del l2cap_mtu
    address = SockaddrL2()
    address.family = AF_BLUETOOTH
    address.bdaddr_type = BDADDR_PUBLIC
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.bind(sock.fileno(), ctypes.byref(address), ctypes.sizeof(address)) < 0:
        error = ctypes.get_errno()
        raise OSError(error, errno.errorcode.get(error, "LE L2CAP bind failed"))
    sock.setsockopt(SOL_BLUETOOTH, BT_MODE, bytes((BT_MODE_LE_FLOWCTL,)))
    sock.setsockopt(SOL_BLUETOOTH, BT_SECURITY, bytes((BT_SECURITY_LOW, 0)))


def connect_le_socket(sock, mac_str, psm, address_type, connect_timeout):
    """Connect with sockaddr_l2 directly when Python lacks LE address tuples."""
    if hasattr(socket, "BDADDR_LE_RANDOM"):
        sock.settimeout(connect_timeout)
        sock.connect((mac_str, psm, 0, address_type))
        sock.settimeout(None)
        return

    address_bytes = bytes.fromhex(mac_str.replace(":", ""))
    if len(address_bytes) != 6:
        raise ValueError(f"Invalid Bluetooth address: {mac_str}")

    address = SockaddrL2()
    address.family = AF_BLUETOOTH
    address.psm = psm
    address.bdaddr[:] = address_bytes[::-1]
    address.cid = 0
    address.bdaddr_type = address_type

    libc = ctypes.CDLL(None, use_errno=True)
    sock.setblocking(False)
    result = libc.connect(
        sock.fileno(), ctypes.byref(address), ctypes.sizeof(address)
    )
    if result < 0:
        error = ctypes.get_errno()
        if error not in (errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK):
            raise OSError(error, errno.errorcode.get(error, "L2CAP connect failed"))

        _, writable, exceptional = select.select(
            [], [sock], [sock], connect_timeout
        )
        if not writable and not exceptional:
            raise TimeoutError(f"L2CAP connect timed out after {connect_timeout}s")
        error = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if error:
            raise OSError(error, errno.errorcode.get(error, "L2CAP connect failed"))

    sock.setblocking(True)


def connect_le_l2cap(mac_str, psm, address_type, retries, retry_delay, connect_timeout, l2cap_mtu):
    for attempt in range(1, retries + 1):
        sock = socket.socket(AF_BLUETOOTH, socket.SOCK_SEQPACKET, BTPROTO_L2CAP)
        configure_l2cap_socket(sock, l2cap_mtu)
        sock.settimeout(connect_timeout)
        print(
            f"[BLE] L2CAP connect {attempt}/{retries}: {mac_str}, "
            f"PSM 0x{psm:04x}, addr_type {address_type}"
        )

        try:
            connect_le_socket(
                sock, mac_str, psm, address_type, connect_timeout
            )
            print("[BLE] L2CAP channel established")
            rcv_mtu = read_u16_sockopt(sock, SOL_BLUETOOTH, BT_RCVMTU)
            snd_mtu = read_u16_sockopt(sock, SOL_BLUETOOTH, BT_SNDMTU)
            if rcv_mtu or snd_mtu:
                print(f"[BLE] Negotiated MTU: rcv={rcv_mtu or '?'} snd={snd_mtu or '?'}")
            return sock
        except OSError as exc:
            print(f"[BLE] connect failed: {exc}")

        sock.close()
        if attempt % 10 == 0 and attempt < retries:
            print("[BLE] Recycling the adapter after repeated controller failures")
            run_host_cmd(["bluetoothctl", "power", "off"], timeout=5)
            time.sleep(1)
            run_host_cmd(["bluetoothctl", "power", "on"], timeout=5)
            run_host_cmd(
                ["bluetoothctl", "--timeout", "2", "scan", "on"], timeout=4
            )
            run_host_cmd(["bluetoothctl", "scan", "off"], timeout=5)
        time.sleep(retry_delay)

    raise OSError("BLE L2CAP retry limit reached")


def forward_tcp_to_ble(source, destination, ble_write_chunk):
    try:
        while True:
            data = source.recv(4096)
            if not data:
                break

            offset = 0
            while offset < len(data):
                chunk = data[offset : offset + ble_write_chunk]
                destination.sendall(chunk)
                offset += len(chunk)
                if offset < len(data):
                    time.sleep(0.02)
    except OSError as exc:
        print(f"[BRIDGE] TCP->BLE stopped: {exc}")
    finally:
        close_pair(source, destination)


def forward_ble_to_tcp(source, destination, strip_sdu_prefix):
    pending = bytearray()
    expected_sdu_len = None
    first_packet = True
    framing_decided = not strip_sdu_prefix

    try:
        while True:
            data = source.recv(4096)
            if not data:
                break
            if first_packet:
                print(
                    f"[BRIDGE] First BLE receive: {len(data)} bytes, "
                    f"prefix={data[:12].hex(' ')}"
                )
                first_packet = False

            if not framing_decided:
                # Proper LE flow-control sockets return a complete TLS SDU.
                # Some Raspberry Pi kernel/controller combinations expose
                # the two-byte SDU length followed by MPS-sized fragments.
                strip_sdu_prefix = (
                    len(data) >= 5
                    and data[2] in (20, 21, 22, 23)
                    and data[3] == 3
                )
                framing_decided = True
                print(
                    "[BRIDGE] BLE receive framing: "
                    + ("fragmented SDU prefix" if strip_sdu_prefix else "complete SDU")
                )

            if not strip_sdu_prefix:
                destination.sendall(data)
                continue

            pending.extend(data)
            while pending:
                if expected_sdu_len is None:
                    if len(pending) < 2:
                        break
                    expected_sdu_len = int.from_bytes(pending[:2], "little")
                    del pending[:2]
                    if expected_sdu_len == 0:
                        expected_sdu_len = None
                        continue

                chunk_len = min(expected_sdu_len, len(pending))
                if chunk_len == 0:
                    break
                destination.sendall(pending[:chunk_len])
                del pending[:chunk_len]
                expected_sdu_len -= chunk_len
                if expected_sdu_len == 0:
                    expected_sdu_len = None
    except OSError as exc:
        print(f"[BRIDGE] BLE->TCP stopped: {exc}")
    finally:
        close_pair(source, destination)


def close_pair(*sockets):
    for sock in sockets:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass


def build_args():
    parser = argparse.ArgumentParser(
        description="Raw BLE L2CAP CoC to TCP gateway for the peripheral TLS/MQTT demo."
    )
    parser.add_argument("--addr", default="", help="nRF52840 BLE address; discovered by name if omitted")
    parser.add_argument("--name", default=DEFAULT_BLE_NAME, help="BLE name used when --addr is omitted")
    parser.add_argument("--psm", type=lambda value: int(value, 0), default=DEFAULT_PSM)
    parser.add_argument("--addr-type", choices=("public", "random"), default="random")
    parser.add_argument("--broker-host", default=DEFAULT_BROKER_HOST)
    parser.add_argument("--broker-port", type=int, default=DEFAULT_BROKER_PORT)
    parser.add_argument("--scan-seconds", type=float, default=4.0)
    parser.add_argument("--forget-cache", action="store_true")
    parser.add_argument("--retries", type=int, default=60)
    parser.add_argument("--retry-delay", type=float, default=0.5)
    parser.add_argument("--connect-timeout", type=float, default=10.0)
    parser.add_argument("--l2cap-mtu", type=int, default=DEFAULT_L2CAP_MTU)
    parser.add_argument("--ble-write-chunk", type=int, default=DEFAULT_BLE_WRITE_CHUNK)
    parser.add_argument(
        "--no-strip-sdu-prefix",
        action="store_true",
        help="Forward BLE receives as-is; Raspberry Pi kernels normally expose a two-byte LE CoC SDU length prefix.",
    )
    return parser.parse_args()


def main():
    args = build_args()
    address_type = BDADDR_RANDOM if args.addr_type == "random" else BDADDR_PUBLIC

    try:
        if not args.addr:
            args.addr = discover_ble_address(args.name, args.scan_seconds)
            scan_seconds = 0
        else:
            scan_seconds = args.scan_seconds
        prepare_bluetooth_adapter(args.addr, scan_seconds, args.forget_cache)
        establish_acl_connection(args.addr)
        ble_sock = connect_le_l2cap(
            args.addr,
            args.psm,
            address_type,
            args.retries,
            args.retry_delay,
            args.connect_timeout,
            args.l2cap_mtu,
        )

        print(f"[TCP] Connecting to Mosquitto at {args.broker_host}:{args.broker_port}")
        tcp_sock = socket.create_connection((args.broker_host, args.broker_port), timeout=10)
        tcp_sock.settimeout(None)
        print("[BRIDGE] Raw BLE L2CAP <-> TCP bridge is active")

        to_tcp = threading.Thread(
            target=forward_ble_to_tcp,
            args=(ble_sock, tcp_sock, not args.no_strip_sdu_prefix),
        )
        to_ble = threading.Thread(
            target=forward_tcp_to_ble,
            args=(tcp_sock, ble_sock, args.ble_write_chunk),
        )
        to_tcp.start()
        to_ble.start()
        to_tcp.join()
        to_ble.join()
    except KeyboardInterrupt:
        print("[BRIDGE] Interrupted")
    except Exception as exc:
        print(f"[BRIDGE] Failed: {exc}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
