from siem_anomaly.core import (
    Capability,
    CapabilityName,
    DetectorRequirement,
    discover_compatible,
)


def test_discovery_is_provider_neutral() -> None:
    capabilities = (
        Capability(CapabilityName.ACTOR, "principal", "authenticated_principal"),
        Capability(CapabilityName.SOURCE_IP, "client_ip", "client_origin"),
    )
    requirements = (
        DetectorRequirement(
            "generic.first_seen_actor_ip",
            frozenset({CapabilityName.ACTOR, CapabilityName.SOURCE_IP}),
        ),
        DetectorRequirement(
            "generic.resource_change",
            frozenset({CapabilityName.ACTOR, CapabilityName.TARGET}),
        ),
    )

    results = discover_compatible(capabilities, requirements)

    assert results[0].compatible is True
    assert results[1].compatible is False
    assert results[1].missing == (CapabilityName.TARGET,)
