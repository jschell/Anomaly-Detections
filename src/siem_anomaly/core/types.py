from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


class ActorType(StrEnum):
    HUMAN = "human"
    SERVICE_ACCOUNT = "service_account"
    SERVICE_PRINCIPAL = "service_principal"
    MANAGED_IDENTITY = "managed_identity"
    ROLE = "role"
    WORKLOAD_IDENTITY = "workload_identity"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    detector_id: str
    entity: str
    start: datetime
    end: datetime
    score: float
    reasons: tuple[str, ...]
