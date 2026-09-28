from datetime import UTC, datetime

from siem_anomaly.core.domain import Actor, ActorType, EventEnvelope, Resource


def test_provider_neutral_domain_records_are_immutable() -> None:
    actor = Actor(id="user-1", type=ActorType.HUMAN, display_name="Analyst")
    resource = Resource(id="resource-1", type="vault", service="key-management")
    event = EventEnvelope(
        timestamp=datetime(2026, 9, 28, 12, tzinfo=UTC),
        provider="example",
        source="example.audit",
        event_type="access",
        actor=actor,
        action="read",
        target=resource,
    )
    assert event.actor == actor
    assert event.target == resource
