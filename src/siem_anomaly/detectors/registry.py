"""Capability-driven detector discovery."""

from dataclasses import dataclass

from siem_anomaly.core.capabilities import Capability
from siem_anomaly.core.profile import DataProfile


@dataclass(frozen=True, slots=True)
class DetectorSpec:
    detector_id: str
    required_capabilities: frozenset[Capability]
    description: str


@dataclass(frozen=True, slots=True)
class DetectorRegistry:
    specs: tuple[DetectorSpec, ...]

    def discover(self, profile: DataProfile) -> tuple[DetectorSpec, ...]:
        return tuple(
            spec for spec in self.specs if spec.required_capabilities <= profile.capabilities
        )


def build_default_registry() -> DetectorRegistry:
    actor_ip = frozenset({Capability.ACTOR, Capability.SOURCE_IP})
    actor_time = frozenset({Capability.ACTOR, Capability.TIMESTAMP})
    return DetectorRegistry(
        specs=(
            DetectorSpec(
                "identity.relationship_novelty",
                actor_ip,
                "Actor/source-IP relationship not present in historical state.",
            ),
            DetectorSpec(
                "identity.conditional_rarity",
                actor_ip,
                "Actor/source-IP relationship is historically rare.",
            ),
            DetectorSpec(
                "identity.relationship_change",
                actor_ip,
                "Established actor forms a new source-IP relationship.",
            ),
            DetectorSpec(
                "identity.rhythm_deviation",
                actor_time,
                "Actor activity occurs outside established hour/weekday rhythm.",
            ),
            DetectorSpec(
                "identity.volume_deviation",
                actor_time,
                "Actor hourly volume exceeds its historical p95 baseline.",
            ),
            DetectorSpec(
                "identity.robust_historical_deviation",
                actor_time,
                "Actor hourly volume deviates strongly from median/MAD history.",
            ),
            DetectorSpec(
                "identity.organization_relative_deviation",
                actor_time,
                "Actor volume is extreme relative to organization peers at that time.",
            ),
        )
    )
