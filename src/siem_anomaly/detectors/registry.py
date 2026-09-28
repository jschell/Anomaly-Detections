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
    return DetectorRegistry(
        specs=(
            DetectorSpec(
                "identity.relationship_novelty",
                frozenset({Capability.ACTOR, Capability.SOURCE_IP}),
                "Actor/source-IP relationship not present in historical state.",
            ),
            DetectorSpec(
                "identity.conditional_rarity",
                frozenset({Capability.ACTOR, Capability.SOURCE_IP}),
                "Actor/source-IP relationship is historically rare.",
            ),
            DetectorSpec(
                "identity.rhythm_deviation",
                frozenset({Capability.ACTOR, Capability.TIMESTAMP}),
                "Actor activity occurs outside established hour/weekday rhythm.",
            ),
            DetectorSpec(
                "identity.volume_deviation",
                frozenset({Capability.ACTOR, Capability.TIMESTAMP}),
                "Actor hourly volume exceeds its historical rhythm baseline.",
            ),
        )
    )
