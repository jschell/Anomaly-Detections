"""Explicit promotion of selected in-memory records into incident evidence."""

from dataclasses import dataclass
from pathlib import Path

from siem_anomaly.adapters.frames import TabularData, to_polars
from siem_anomaly.persistence.policy import ArtifactKind, PersistencePolicy


@dataclass(frozen=True, slots=True)
class IncidentEvidenceStore:
    root: Path
    policy: PersistencePolicy

    def promote(self, incident_id: str, data: TabularData, *, filename: str = "events.parquet") -> Path:
        """Persist selected full events through an explicitly incident-scoped API."""
        self.policy.assert_allowed(ArtifactKind.INCIDENT_EVIDENCE, explicit_incident=True)
        if not incident_id.strip():
            raise ValueError("incident_id must not be empty")
        incident_dir = self.root / incident_id
        incident_dir.mkdir(parents=True, exist_ok=True)
        destination = incident_dir / filename
        to_polars(data).write_parquet(destination)
        return destination
