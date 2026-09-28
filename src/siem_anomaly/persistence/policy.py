"""Persistence policy enforcement for engagement artifacts."""

from dataclasses import dataclass
from enum import StrEnum


class ArtifactKind(StrEnum):
    RAW_EVENT = "raw_event"
    AGGREGATE_FEATURE = "aggregate_feature"
    RELATIONSHIP_STATE = "relationship_state"
    BASELINE = "baseline"
    MODEL = "model"
    FINDING = "finding"
    EVALUATION_RESULT = "evaluation_result"
    MANIFEST = "manifest"
    INCIDENT_EVIDENCE = "incident_evidence"


_DERIVED_ALLOWED = frozenset(
    {
        ArtifactKind.AGGREGATE_FEATURE,
        ArtifactKind.RELATIONSHIP_STATE,
        ArtifactKind.BASELINE,
        ArtifactKind.MODEL,
        ArtifactKind.FINDING,
        ArtifactKind.EVALUATION_RESULT,
        ArtifactKind.MANIFEST,
    }
)


@dataclass(frozen=True, slots=True)
class PersistencePolicy:
    """Central policy for deciding which artifact types may be persisted."""

    allow_incident_evidence: bool = True

    def assert_allowed(self, kind: ArtifactKind, *, explicit_incident: bool = False) -> None:
        if kind in _DERIVED_ALLOWED:
            return
        if kind is ArtifactKind.INCIDENT_EVIDENCE and self.allow_incident_evidence and explicit_incident:
            return
        if kind is ArtifactKind.RAW_EVENT:
            raise PermissionError("Ordinary raw SIEM events may not be persisted")
        raise PermissionError(f"Persistence not allowed for artifact kind: {kind}")
