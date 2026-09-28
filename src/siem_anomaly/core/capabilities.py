from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable


class CapabilityName(StrEnum):
    TIMESTAMP = "timestamp"
    ACTOR = "actor"
    ACTOR_TYPE = "actor_type"
    ACTION = "action"
    TARGET = "target"
    SOURCE_IP = "source_ip"
    APPLICATION = "application"
    OUTCOME = "outcome"
    REGION = "region"
    COUNTRY = "country"
    DEVICE = "device"
    AUTHENTICATION = "authentication"


@dataclass(frozen=True, slots=True)
class Capability:
    name: CapabilityName
    field: str
    semantic_role: str
    completeness: float = 1.0

    def __post_init__(self) -> None:
        if not 0.0 <= self.completeness <= 1.0:
            raise ValueError("completeness must be between 0.0 and 1.0")


@dataclass(frozen=True, slots=True)
class DetectorRequirement:
    detector_id: str
    requires: frozenset[CapabilityName]


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    detector_id: str
    compatible: bool
    missing: tuple[CapabilityName, ...]


def discover_compatible(
    capabilities: Iterable[Capability],
    requirements: Iterable[DetectorRequirement],
) -> tuple[DiscoveryResult, ...]:
    available = {capability.name for capability in capabilities}
    results: list[DiscoveryResult] = []
    for requirement in requirements:
        missing = tuple(sorted(requirement.requires - available, key=str))
        results.append(
            DiscoveryResult(
                detector_id=requirement.detector_id,
                compatible=not missing,
                missing=missing,
            )
        )
    return tuple(results)
