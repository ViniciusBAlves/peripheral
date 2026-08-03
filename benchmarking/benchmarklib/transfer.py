from __future__ import annotations

import hashlib
import random
import statistics
from dataclasses import dataclass


PAYLOAD_SIZES = (1024, 10 * 1024, 100 * 1024)
DIRECTIONS = ("server_to_device", "device_to_server")


@dataclass(frozen=True)
class TransferOperation:
    order: int
    direction: str
    payload_bytes: int
    payload_seed: int


@dataclass(frozen=True)
class TransferRound:
    sequence: int
    case_id: str
    round_index: int
    operations: tuple[TransferOperation, ...]

    # Compatibility with the normal runner's atomic SessionJob interface.
    @property
    def session(self) -> int:
        return self.round_index

    @property
    def attempt_in_session(self) -> int:
        return 1

    @property
    def warmup(self) -> int:
        return 0

    @property
    def measured_index(self) -> int:
        return self.round_index


def derived_seed(seed: int, case_id: str, round_index: int) -> int:
    material = f"{seed}:{case_id}:{round_index}".encode("utf-8")
    return int.from_bytes(hashlib.sha256(material).digest()[:4], "big")


def payload_byte(seed: int, offset: int) -> int:
    return (seed + offset * 31 + (offset >> 8) * 17) & 0xFF


def payload_bytes(seed: int, size: int) -> bytes:
    return bytes(payload_byte(seed, offset) for offset in range(size))


def payload_sha256(seed: int, size: int, chunk_size: int = 1024) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        count = min(chunk_size, size - offset)
        digest.update(bytes(
            payload_byte(seed, index)
            for index in range(offset, offset + count)
        ))
        offset += count
    return digest.hexdigest()


def operations_for_round(
    seed: int, case_id: str, round_index: int,
) -> tuple[TransferOperation, ...]:
    round_seed = derived_seed(seed, case_id, round_index)
    pairs = [
        (direction, size)
        for size in PAYLOAD_SIZES
        for direction in DIRECTIONS
    ]
    random.Random(round_seed).shuffle(pairs)
    return tuple(
        TransferOperation(
            order=index,
            direction=direction,
            payload_bytes=size,
            payload_seed=derived_seed(round_seed, direction, size),
        )
        for index, (direction, size) in enumerate(pairs, 1)
    )


def build_transfer_rounds(
    cases: list[dict[str, str]], *, seed: int,
) -> list[TransferRound]:
    rounds: list[TransferRound] = []
    sequence = 0
    for case in cases:
        for round_index in range(1, int(case["iterations"]) + 1):
            sequence += 1
            rounds.append(TransferRound(
                sequence=sequence,
                case_id=case["case_id"],
                round_index=round_index,
                operations=operations_for_round(
                    seed, case["case_id"], round_index
                ),
            ))
    random.Random(seed).shuffle(rounds)
    return rounds


def encode_remaining_length(value: int) -> bytes:
    if not 0 <= value <= 268_435_455:
        raise ValueError("MQTT remaining length is out of range")
    encoded = bytearray()
    while True:
        digit = value % 128
        value //= 128
        if value:
            digit |= 0x80
        encoded.append(digit)
        if not value:
            return bytes(encoded)


def mqtt_publish_header(topic: str, packet_id: int, payload_size: int) -> bytes:
    topic_bytes = topic.encode("utf-8")
    variable = (
        len(topic_bytes).to_bytes(2, "big") + topic_bytes +
        packet_id.to_bytes(2, "big")
    )
    return b"\x32" + encode_remaining_length(len(variable) + payload_size) + variable


def percentile_95(values: list[float]) -> float:
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    index = 0.95 * (len(ordered) - 1)
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = index - lower
    return ordered[lower] + (ordered[upper] - ordered[lower]) * fraction


def confidence_95_half_width(values: list[float]) -> float | None:
    if len(values) < 2:
        return None
    return 1.96 * statistics.stdev(values) / len(values) ** 0.5
