from __future__ import annotations

import random
from dataclasses import dataclass


@dataclass(frozen=True)
class SessionJob:
    sequence: int
    case_id: str
    session: int
    attempt_in_session: int
    warmup: int
    measured_index: int


def build_jobs(
    cases: list[dict[str, str]],
    *,
    seed: int,
    sessions_per_case: int = 2,
) -> list[SessionJob]:
    normal_jobs: list[SessionJob] = []
    deferred_groups: list[list[SessionJob]] = []
    sequence = 0
    for case in cases:
        case_jobs: list[SessionJob] = []
        warmups = int(case["warmup_iterations"])
        iterations = int(case["iterations"])
        for session in range(1, sessions_per_case + 1):
            for attempt in range(1, warmups + iterations + 1):
                sequence += 1
                is_warmup = attempt <= warmups
                case_jobs.append(
                    SessionJob(
                        sequence=sequence,
                        case_id=case["case_id"],
                        session=session,
                        attempt_in_session=attempt,
                        warmup=int(is_warmup),
                        measured_index=0 if is_warmup else attempt - warmups,
                    )
                )
        if case.get("expected_support") == "known_unsupported":
            deferred_groups.append(case_jobs)
        else:
            normal_jobs.extend(case_jobs)

    rng = random.Random(seed)
    rng.shuffle(normal_jobs)
    rng.shuffle(deferred_groups)

    # Large-RSA fallback cases share one firmware profile. Keeping every case
    # contiguous avoids repeated reflashes while retaining seeded case order.
    return normal_jobs + [job for group in deferred_groups for job in group]
