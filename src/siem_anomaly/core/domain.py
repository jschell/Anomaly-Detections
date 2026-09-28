"""Provider-neutral domain records used across adapters and findings."""

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
    API_TOKEN = "api_token"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Actor:
    id: str
    type: ActorType = ActorType.UNKNOWN
    display_name: str | None = None


@dataclass(frozen=True, slots=True)
class Resource:
    id: str
    type: str | None = None
    service: str | None = None
    region: str | None = None


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    timestamp: datetime
    provider: str
    source: str
    event_type: str
    actor: Actor | None = None
    action: str | None = None
    target: Resource | None = None
    source_ip: str | None = None
    outcome: str | None = None


@dataclass(frozen=True, slots=True)
class Finding:
    finding_id: str
    detector_id: str
    source: str
    start: datetime
    end: datetime
    score: float
    entity: str | None = None
    reason_codes: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()

    def query_context(self) -> dict[str, str]:
        context = {
            "source": self.source,
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
        }
        if self.entity is not None:
            context["entity"] = self.entity
        return context
