from siem_anomaly.feature_catalog import (
    FeatureMaturity,
    PortabilityExpectation,
    build_core_feature_registry,
)


def test_core_feature_registry_documents_storage_consumers_and_portability() -> None:
    registry = build_core_feature_registry()
    feature = registry.get("identity.actor_source_ip.rarity_score")
    assert feature.persisted
    assert feature.storage_class == "relationship_state"
    assert feature.maturity is FeatureMaturity.CORE
    assert feature.portability is PortabilityExpectation.HIGH
    assert "identity.conditional_rarity" in feature.consumers


def test_registry_distinguishes_persisted_and_on_demand_features() -> None:
    registry = build_core_feature_registry()
    robust = registry.get("identity.robust_deviation")
    assert not robust.persisted
    assert robust.storage_class == "detector_feature"
