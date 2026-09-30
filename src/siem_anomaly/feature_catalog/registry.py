"""Formal registry for persisted and detector-derived behavioral features."""

from dataclasses import dataclass
from enum import StrEnum


class FeatureMaturity(StrEnum):
    EXPERIMENTAL = "experimental"
    CANDIDATE = "candidate"
    VALIDATED = "validated"
    CORE = "core"
    DEPRECATED = "deprecated"


class PortabilityExpectation(StrEnum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class FeatureDefinition:
    feature_id: str
    version: str
    family: str
    persisted: bool
    storage_class: str
    resolution: str
    consumers: tuple[str, ...]
    maturity: FeatureMaturity
    portability: PortabilityExpectation
    description: str


@dataclass(frozen=True, slots=True)
class FeatureRegistry:
    features: tuple[FeatureDefinition, ...]

    def get(self, feature_id: str) -> FeatureDefinition:
        for feature in self.features:
            if feature.feature_id == feature_id:
                return feature
        raise KeyError(feature_id)

    def by_maturity(self, maturity: FeatureMaturity) -> tuple[FeatureDefinition, ...]:
        return tuple(feature for feature in self.features if feature.maturity is maturity)


def build_core_feature_registry() -> FeatureRegistry:
    relationship_consumers = (
        "identity.relationship_novelty",
        "identity.conditional_rarity",
        "identity.relationship_change",
    )
    return FeatureRegistry(
        features=(
            FeatureDefinition(
                "identity.actor_hour.event_count",
                "1",
                "identity_temporal",
                True,
                "aggregate_feature",
                "1h",
                (
                    "identity.volume_deviation",
                    "identity.robust_historical_deviation",
                    "identity.organization_relative_deviation",
                ),
                FeatureMaturity.CORE,
                PortabilityExpectation.HIGH,
                "Hourly event count for an actor.",
            ),
            FeatureDefinition(
                "identity.actor_hour.unique_ips",
                "1",
                "identity_diversity",
                True,
                "aggregate_feature",
                "1h",
                (),
                FeatureMaturity.CANDIDATE,
                PortabilityExpectation.HIGH,
                "Unique source IP count per actor-hour.",
            ),
            FeatureDefinition(
                "identity.actor_source_ip.event_count",
                "1",
                "identity_relationship",
                True,
                "relationship_state",
                "90d",
                relationship_consumers,
                FeatureMaturity.CORE,
                PortabilityExpectation.HIGH,
                "Historical event count for actor/source-IP relationship.",
            ),
            FeatureDefinition(
                "identity.actor_source_ip.days_seen",
                "1",
                "identity_relationship",
                True,
                "relationship_state",
                "90d",
                relationship_consumers,
                FeatureMaturity.CORE,
                PortabilityExpectation.HIGH,
                "Days an actor/source-IP relationship has appeared.",
            ),
            FeatureDefinition(
                "identity.actor_source_ip.rarity_score",
                "1",
                "identity_relationship",
                True,
                "relationship_state",
                "90d",
                relationship_consumers,
                FeatureMaturity.CORE,
                PortabilityExpectation.HIGH,
                "Inverse-frequency rarity of actor/source-IP relationship.",
            ),
            FeatureDefinition(
                "identity.rhythm.weekday_hour",
                "1",
                "identity_temporal",
                True,
                "baseline",
                "weekday_hour",
                ("identity.rhythm_deviation",),
                FeatureMaturity.CORE,
                PortabilityExpectation.HIGH,
                "Actor weekday/hour median and p95 activity rhythm.",
            ),
            FeatureDefinition(
                "identity.robust_deviation",
                "1",
                "identity_temporal",
                False,
                "detector_feature",
                "on_demand",
                ("identity.robust_historical_deviation",),
                FeatureMaturity.VALIDATED,
                PortabilityExpectation.HIGH,
                "Median/MAD relative deviation calculated from stored aggregates.",
            ),
            FeatureDefinition(
                "identity.actor_asn.relationship",
                "1",
                "network_relationship",
                True,
                "relationship_state",
                "90d",
                ("identity.asn_novelty", "identity.asn_change"),
                FeatureMaturity.CANDIDATE,
                PortabilityExpectation.MEDIUM,
                "Actor/ASN historical count, dates, and days seen.",
            ),
            FeatureDefinition(
                "identity.actor_hour.unique_asns",
                "1",
                "network_diversity",
                True,
                "aggregate_feature",
                "1h",
                ("identity.asn_diversity",),
                FeatureMaturity.CANDIDATE,
                PortabilityExpectation.MEDIUM,
                "Distinct valid ASNs observed for an actor-hour.",
            ),
            FeatureDefinition(
                "identity.actor_network_trait.relationship",
                "1",
                "network_relationship",
                True,
                "relationship_state",
                "90d",
                ("identity.network_trait_novelty",),
                FeatureMaturity.EXPERIMENTAL,
                PortabilityExpectation.LOW,
                "Actor/network classification history from versioned enrichment.",
            ),
        )
    )
