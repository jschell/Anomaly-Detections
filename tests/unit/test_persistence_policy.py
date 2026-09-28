import pytest

from siem_anomaly.persistence import ArtifactKind, PersistencePolicy


def test_raw_event_persistence_is_rejected() -> None:
    with pytest.raises(PermissionError):
        PersistencePolicy().assert_allowed(ArtifactKind.RAW_EVENT)


def test_incident_evidence_requires_explicit_scope() -> None:
    policy = PersistencePolicy()
    with pytest.raises(PermissionError):
        policy.assert_allowed(ArtifactKind.INCIDENT_EVIDENCE)
    policy.assert_allowed(ArtifactKind.INCIDENT_EVIDENCE, explicit_incident=True)
