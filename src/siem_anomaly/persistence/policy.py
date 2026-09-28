from __future__ import annotations

from dataclasses import dataclass

from .artifact_types import ArtifactType


@dataclass(frozen=True, slots=True)
class PersistencePolicy:
    allow_incident_evidence: bool = True

    def validate(
        self,
        artifact_type: ArtifactType,
        *,
        explicit_incident_promotion: bool = False,
    ) -> None:
        if artifact_type is ArtifactType.INCIDENT_EVIDENCE:
            if not self.allow_incident_evidence:
                raise PermissionError("Incident evidence persistence is disabled")
            if not explicit_incident_promotion:
                raise PermissionError("Raw incident evidence requires explicit promotion")
