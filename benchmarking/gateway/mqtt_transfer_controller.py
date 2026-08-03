#!/usr/bin/env python3
"""Drive the benchmark board through a local, plaintext Mosquitto listener."""

from __future__ import annotations

import argparse
import hashlib
import json
import socket
import time
from collections import deque


TOPIC_CONTROL = "bench/control"
TOPIC_DOWN = "bench/down"
TOPIC_UP = "bench/up"
TOPIC_DEVICE_ACK = "bench/device_ack"
TOPIC_METRICS = "bench/metrics"


def encode_remaining_length(value: int) -> bytes:
    output = bytearray()
    while True:
        digit = value % 128
        value //= 128
        if value:
            digit |= 0x80
        output.append(digit)
        if not value:
            return bytes(output)


def encode_utf8(value: str) -> bytes:
    data = value.encode()
    return len(data).to_bytes(2, "big") + data


def payload_byte(seed: int, offset: int) -> int:
    return (seed + offset * 31 + (offset >> 8) * 17) & 0xFF


def make_payload(seed: int, size: int) -> bytes:
    return bytes(payload_byte(seed, offset) for offset in range(size))


def payload_hash(seed: int, size: int) -> str:
    digest = hashlib.sha256()
    for offset in range(0, size, 1024):
        count = min(1024, size - offset)
        digest.update(bytes(
            payload_byte(seed, index) for index in range(offset, offset + count)
        ))
    return digest.hexdigest()


class MqttClient:
    def __init__(self, host: str, port: int, timeout: float):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.packet_id = 1
        self.inbox: deque[tuple[str, bytes, int]] = deque()

    def close(self) -> None:
        try:
            self.sock.sendall(b"\xe0\x00")
        except OSError:
            pass
        self.sock.close()

    def _next_id(self) -> int:
        value = self.packet_id
        self.packet_id = 1 if value == 65535 else value + 1
        return value

    def _read_exact(self, size: int) -> bytes:
        output = bytearray()
        while len(output) < size:
            chunk = self.sock.recv(size - len(output))
            if not chunk:
                raise ConnectionError("MQTT broker closed the connection")
            output.extend(chunk)
        return bytes(output)

    def read_packet(self) -> tuple[int, bytes]:
        first, remaining = self.read_packet_header()
        return first, self._read_exact(remaining)

    def read_packet_header(self) -> tuple[int, int]:
        first = self._read_exact(1)[0]
        remaining = 0
        multiplier = 1
        for _ in range(4):
            digit = self._read_exact(1)[0]
            remaining += (digit & 0x7F) * multiplier
            if not digit & 0x80:
                return first, remaining
            multiplier *= 128
        raise ValueError("malformed MQTT remaining length")

    def connect(self) -> None:
        body = encode_utf8("MQTT") + b"\x04\x02\x00\x3c" + encode_utf8(
            "transfer-controller"
        )
        self.sock.sendall(b"\x10" + encode_remaining_length(len(body)) + body)
        packet, body = self.read_packet()
        if packet != 0x20 or body != b"\x00\x00":
            raise RuntimeError(f"MQTT CONNACK rejected: {packet:#x} {body!r}")

    def subscribe(self, topics: tuple[str, ...]) -> None:
        packet_id = self._next_id()
        body = packet_id.to_bytes(2, "big") + b"".join(
            encode_utf8(topic) + b"\x01" for topic in topics
        )
        self.sock.sendall(b"\x82" + encode_remaining_length(len(body)) + body)
        while True:
            packet, response = self.read_packet()
            if packet == 0x90 and response[:2] == packet_id.to_bytes(2, "big"):
                return
            self._store_publish(packet, response)

    def _store_publish(self, packet: int, body: bytes) -> None:
        if packet >> 4 != 3:
            return
        topic_len = int.from_bytes(body[:2], "big")
        topic = body[2:2 + topic_len].decode()
        offset = 2 + topic_len
        qos = (packet >> 1) & 0x03
        packet_id = 0
        if qos:
            packet_id = int.from_bytes(body[offset:offset + 2], "big")
            offset += 2
            self.sock.sendall(b"\x40\x02" + packet_id.to_bytes(2, "big"))
        self.inbox.append((topic, body[offset:], packet_id))

    def _wait_puback(self, packet_id: int) -> None:
        expected = packet_id.to_bytes(2, "big")
        while True:
            packet, body = self.read_packet()
            if packet == 0x40 and body == expected:
                return
            self._store_publish(packet, body)

    def publish(self, topic: str, payload: bytes) -> None:
        packet_id = self._next_id()
        body = encode_utf8(topic) + packet_id.to_bytes(2, "big") + payload
        self.sock.sendall(b"\x32" + encode_remaining_length(len(body)) + body)
        self._wait_puback(packet_id)

    def publish_pattern(self, topic: str, seed: int, size: int) -> None:
        packet_id = self._next_id()
        variable = encode_utf8(topic) + packet_id.to_bytes(2, "big")
        self.sock.sendall(
            b"\x32" + encode_remaining_length(len(variable) + size) + variable
        )
        for offset in range(0, size, 1024):
            count = min(1024, size - offset)
            self.sock.sendall(bytes(
                payload_byte(seed, index)
                for index in range(offset, offset + count)
            ))
        self._wait_puback(packet_id)

    def wait_pattern_publish(self, topic: str, seed: int, size: int) -> tuple[str, bool]:
        packet, remaining = self.read_packet_header()
        if packet >> 4 != 3:
            raise RuntimeError(f"expected MQTT PUBLISH, received {packet:#x}")
        topic_size = int.from_bytes(self._read_exact(2), "big")
        actual_topic = self._read_exact(topic_size).decode()
        qos = (packet >> 1) & 0x03
        packet_id = int.from_bytes(self._read_exact(2), "big") if qos else 0
        payload_size = remaining - 2 - topic_size - (2 if qos else 0)
        digest = hashlib.sha256()
        valid = actual_topic == topic and payload_size == size
        offset = 0
        while offset < payload_size:
            chunk = self._read_exact(min(1024, payload_size - offset))
            digest.update(chunk)
            valid &= all(
                value == payload_byte(seed, offset + index)
                for index, value in enumerate(chunk)
            )
            offset += len(chunk)
        if packet_id:
            self.sock.sendall(b"\x40\x02" + packet_id.to_bytes(2, "big"))
        return digest.hexdigest(), valid

    def wait_publish(self, topic: str) -> bytes:
        while True:
            for index, item in enumerate(self.inbox):
                if item[0] == topic:
                    del self.inbox[index]
                    return item[1]
            packet, body = self.read_packet()
            self._store_publish(packet, body)


def run(plan: dict[str, object], host: str, port: int, timeout: float) -> None:
    client = MqttClient(host, port, timeout)
    try:
        client.connect()
        client.subscribe((TOPIC_UP, TOPIC_DEVICE_ACK, TOPIC_METRICS))
        ready = client.wait_publish(TOPIC_UP)
        if ready != b"READY":
            raise RuntimeError(f"expected board READY, received {ready[:80]!r}")
        print("[BENCH_TRANSFER_SERVER] status=ready", flush=True)

        for operation in plan["operations"]:
            sequence = int(operation["order"])
            direction = str(operation["direction"])
            size = int(operation["payload_bytes"])
            seed = int(operation["payload_seed"])
            client.sock.settimeout(
                30.0 if size <= 1024 else 120.0 if size <= 10240 else 600.0
            )
            expected = payload_hash(seed, size)
            command = f"{'DOWN' if direction == 'server_to_device' else 'UP'} {sequence} {size} {seed} {expected}"
            client.publish(TOPIC_CONTROL, command.encode())
            started = time.monotonic_ns()
            if direction == "server_to_device":
                client.publish_pattern(TOPIC_DOWN, seed, size)
                ack = client.wait_publish(TOPIC_DEVICE_ACK).decode(errors="replace")
                valid = ack.startswith(f"ACK_DOWN {sequence} 1 {expected}")
                actual = ack.split()[3] if len(ack.split()) >= 4 else ""
            else:
                actual, valid = client.wait_pattern_publish(
                    TOPIC_UP, seed, size
                )
                valid = valid and actual == expected
                client.publish(
                    TOPIC_CONTROL,
                    f"ACK_UP {sequence} {int(valid)} {actual}".encode(),
                )
            elapsed_us = (time.monotonic_ns() - started) // 1000
            device_metrics = client.wait_publish(TOPIC_METRICS).decode(
                errors="replace"
            )
            print(f"[BENCH_TRANSFER_DEVICE] {device_metrics}", flush=True)
            print(
                "[BENCH_TRANSFER_SERVER] "
                f"sequence={sequence} direction={direction} payload_bytes={size} "
                f"status={'success' if valid else 'fail'} integrity_match={int(valid)} "
                f"sha256={actual} server_end_to_end_us={elapsed_us}",
                flush=True,
            )
            if not valid:
                raise RuntimeError(f"payload validation failed for operation {sequence}")
        print("[BENCH_TRANSFER_SERVER] status=complete", flush=True)
    finally:
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan", required=True)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18884)
    parser.add_argument("--timeout", type=float, default=600.0)
    args = parser.parse_args()
    with open(args.plan, encoding="utf-8") as stream:
        plan = json.load(stream)
    run(plan, args.host, args.port, args.timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
