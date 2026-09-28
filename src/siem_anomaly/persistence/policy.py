"""Persistence policy enforcement for engagement artifacts."""

from dataclasses import dataclass
from enum import StrEnum

from siem_anomaly.persistence.config import EngagementConfig


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
    allow_investigating_evidence: bool = True
    investigating_retention_days: int = 14
    incident_retention: str = "engagement"

    @classmethod
    def from_config(cls, config: EngagementConfig) -> "PersistencePolicy":
        return cls(
            allow_incident_evidence=True,
            allow_investigating_evidence=config.evidence.investigating.enabled,
            investigating_retention_days=config.evidence.investigating.retention_days,
            incident_retention=config.evidence.incident.retention,
        )

    def assert_allowed(
        self,
        kind: ArtifactKind,
        *,
        explicit_incident: bool = False,
        investigating: bool = False,
    ) -> None:
        if kind in _DERIVED_ALLOWED:
            return
        incident_allowed = (
            kind is ArtifactKind.INCIDENT_EVIDENCE
            and self.allow_incident_evidence
            and explicit_incident
            and (not investigating or self.allow_investigating_evidence)
        )
        if incident_allowed:
            return
        if kind is ArtifactKind.RAW_EVENT:
            raise PermissionError("Ordinary raw SIEM events may not be persisted")
        raise PermissionError(f"Persistence not allowed for artifact kind: {kind}")

    def describe(self) -> dict[str, str]:
        return {
            "ordinary_raw_telemetry": "prohibited",
            "derived_behavioral_storage": "allowed",
            "investigation_evidence": (
                "allowed" if self.allow_investigating_evidence else "prohibited"
            ),
            "investigation_evidence_retention_days": str(self.investigating_retention_days),
            "incident_evidence_retention": self.incident_retention,
        }
