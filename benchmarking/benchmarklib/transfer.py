from __future__ import annotations

import hashlib
import random
import statistics
from dataclasses import dataclass
from functools import lru_cache


PAYLOAD_SIZES = (128, 1024, 8 * 1024, 16 * 1024, 32 * 1024, 64 * 1024)
DIRECTIONS = ("server_to_device", "device_to_server")
PAYLOAD_PERIOD_SIZE = 1 << 16
_BASE_PAYLOAD_PERIOD = bytes(
    (offset * 31 + (offset >> 8) * 17) & 0xFF
    for offset in range(PAYLOAD_PERIOD_SIZE)
)


def timeout_for_payload(payload_bytes: int) -> float:
    """Return the per-transfer deadline for BLE L2CAP payload streaming."""
    return 30.0


@dataclass(frozen=True)
class TransferOperation:
    order: int
    iteration: int
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


@lru_cache(maxsize=256)
def _payload_period(seed_low_byte: int) -> bytes:
    translation = bytes((value + seed_low_byte) & 0xFF for value in range(256))
    return _BASE_PAYLOAD_PERIOD.translate(translation)


def payload_slice(seed: int, offset: int, size: int) -> bytes:
    """Generate an exact payload slice using its 64 KiB periodic form."""
    if offset < 0 or size < 0:
        raise ValueError("payload offset and size must be non-negative")
    period = _payload_period(seed & 0xFF)
    start = offset % PAYLOAD_PERIOD_SIZE
    first = min(size, PAYLOAD_PERIOD_SIZE - start)
    remaining = size - first
    return (
        period[start:start + first]
        + period * (remaining // PAYLOAD_PERIOD_SIZE)
        + period[:remaining % PAYLOAD_PERIOD_SIZE]
    )


def payload_bytes(seed: int, size: int) -> bytes:
    return payload_slice(seed, 0, size)


@lru_cache(maxsize=1024)
def _payload_sha256(seed_low_byte: int, size: int) -> str:
    digest = hashlib.sha256()
    period = _payload_period(seed_low_byte)
    for _ in range(size // PAYLOAD_PERIOD_SIZE):
        digest.update(period)
    digest.update(period[:size % PAYLOAD_PERIOD_SIZE])
    return digest.hexdigest()


def payload_sha256(seed: int, size: int, chunk_size: int = 1024) -> str:
    if size < 0 or chunk_size <= 0:
        raise ValueError("payload size and chunk size must be positive")
    return _payload_sha256(seed & 0xFF, size)


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
            iteration=round_index,
            direction=direction,
            payload_bytes=size,
            payload_seed=derived_seed(round_seed, direction, size),
        )
        for index, (direction, size) in enumerate(pairs, 1)
    )


def operations_for_case(
    seed: int, case_id: str, iterations: int,
) -> tuple[TransferOperation, ...]:
    """Build and shuffle all repeated transfers for one TLS/MQTT connection."""
    operations = [
        TransferOperation(
            order=0,
            iteration=iteration,
            direction=direction,
            payload_bytes=size,
            payload_seed=derived_seed(
                derived_seed(seed, case_id, iteration), direction, size
            ),
        )
        for iteration in range(1, iterations + 1)
        for size in PAYLOAD_SIZES
        for direction in DIRECTIONS
    ]
    random.Random(derived_seed(seed, case_id, iterations)).shuffle(operations)
    return tuple(
        TransferOperation(
            order=order,
            iteration=operation.iteration,
            direction=operation.direction,
            payload_bytes=operation.payload_bytes,
            payload_seed=operation.payload_seed,
        )
        for order, operation in enumerate(operations, 1)
    )


def build_transfer_rounds(
    cases: list[dict[str, str]], *, seed: int,
) -> list[TransferRound]:
    rounds: list[TransferRound] = []
    for sequence, case in enumerate(cases, 1):
        rounds.append(TransferRound(
            sequence=sequence,
            case_id=case["case_id"],
            round_index=1,
            operations=operations_for_case(
                seed, case["case_id"], int(case["iterations"])
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
