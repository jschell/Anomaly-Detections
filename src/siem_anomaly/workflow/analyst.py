"""Controlled finding-to-investigation-to-incident workflow."""

import json
import shutil
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from siem_anomaly.adapters.frames import TabularData, to_polars
from siem_anomaly.core.domain import Finding
from siem_anomaly.persistence.policy import ArtifactKind, PersistencePolicy


class FindingState(StrEnum):
    UNREVIEWED = "unreviewed"
    INVESTIGATING = "investigating"
    INCIDENT = "incident"
    DISMISSED = "dismissed"


@dataclass(frozen=True, slots=True)
class InvestigationRecord:
    investigation_id: str
    finding_id: str
    source: str
    state: FindingState
    created_at: datetime
    updated_at: datetime
    notes: tuple[str, ...] = ()
    incident_id: str | None = None

    def query_context(self, finding: Finding) -> dict[str, str]:
        return finding.query_context()


@dataclass(frozen=True, slots=True)
class AnalystWorkflow:
    investigations_root: Path
    incidents_root: Path
    policy: PersistencePolicy

    def start(
        self,
        finding: Finding,
        *,
        investigation_id: str,
        note: str | None = None,
    ) -> InvestigationRecord:
        if not investigation_id.strip():
            raise ValueError("investigation_id must not be empty")
        now = datetime.now(UTC)
        record = InvestigationRecord(
            investigation_id=investigation_id,
            finding_id=finding.finding_id,
            source=finding.source,
            state=FindingState.INVESTIGATING,
            created_at=now,
            updated_at=now,
            notes=(note,) if note else (),
        )
        self._write_investigation(record)
        return record

    def add_note(self, record: InvestigationRecord, note: str) -> InvestigationRecord:
        if record.state is FindingState.DISMISSED:
            raise ValueError("Cannot add notes to a dismissed investigation")
        updated = replace(
            record,
            notes=(*record.notes, note),
            updated_at=datetime.now(UTC),
        )
        self._write_record(updated)
        return updated

    def retain_selected_evidence(
        self,
        record: InvestigationRecord,
        data: TabularData,
        *,
        selection_reason: str,
        filename: str = "events.parquet",
    ) -> Path:
        if record.state not in {FindingState.INVESTIGATING, FindingState.INCIDENT}:
            raise ValueError("Evidence may only be retained for an active investigation or incident")
        if not selection_reason.strip():
            raise ValueError("selection_reason must not be empty")
        self.policy.assert_allowed(ArtifactKind.INCIDENT_EVIDENCE, explicit_incident=True)
        root = (
            self.incidents_root / record.incident_id
            if record.state is FindingState.INCIDENT and record.incident_id is not None
            else self.investigations_root / record.investigation_id
        )
        root.mkdir(parents=True, exist_ok=True)
        destination = root / filename
        frame = to_polars(data)
        frame.write_parquet(destination)
        manifest = {
            "finding_id": record.finding_id,
            "investigation_id": record.investigation_id,
            "incident_id": record.incident_id,
            "selected_at": datetime.now(UTC).isoformat(),
            "selection_reason": selection_reason,
            "row_count": frame.height,
            "filename": filename,
        }
        (root / f"{filename}.manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        return destination

    def promote(
        self,
        record: InvestigationRecord,
        *,
        incident_id: str,
        note: str | None = None,
    ) -> InvestigationRecord:
        if record.state is not FindingState.INVESTIGATING:
            raise ValueError("Only an active investigation may be promoted")
        if not incident_id.strip():
            raise ValueError("incident_id must not be empty")
        source_dir = self.investigations_root / record.investigation_id
        incident_dir = self.incidents_root / incident_id
        if incident_dir.exists():
            raise FileExistsError(f"Incident already exists: {incident_id}")
        incident_dir.parent.mkdir(parents=True, exist_ok=True)
        if source_dir.exists():
            shutil.move(str(source_dir), str(incident_dir))
        else:
            incident_dir.mkdir(parents=True, exist_ok=True)
        notes = (*record.notes, note) if note else record.notes
        updated = replace(
            record,
            state=FindingState.INCIDENT,
            incident_id=incident_id,
            notes=notes,
            updated_at=datetime.now(UTC),
        )
        self._write_record(updated)
        return updated

    def dismiss(
        self,
        record: InvestigationRecord,
        *,
        note: str | None = None,
    ) -> InvestigationRecord:
        if record.state is FindingState.INCIDENT:
            raise ValueError("Confirmed incidents are not dismissed by investigation cleanup")
        root = self.investigations_root / record.investigation_id
        if root.exists():
            shutil.rmtree(root)
        notes = (*record.notes, note) if note else record.notes
        updated = replace(
            record,
            state=FindingState.DISMISSED,
            notes=notes,
            updated_at=datetime.now(UTC),
        )
        archive = self.investigations_root / "_dismissed"
        archive.mkdir(parents=True, exist_ok=True)
        self._write_json(archive / f"{record.investigation_id}.json", updated)
        return updated

    def load(self, investigation_id: str) -> InvestigationRecord:
        active = self.investigations_root / investigation_id / "workflow.json"
        dismissed = self.investigations_root / "_dismissed" / f"{investigation_id}.json"
        incident_matches = list(self.incidents_root.glob("*/workflow.json"))
        for path in (active, dismissed, *incident_matches):
            if not path.exists():
                continue
            record = self._read_json(path)
            if record.investigation_id == investigation_id:
                return record
        raise FileNotFoundError(investigation_id)

    def _write_investigation(self, record: InvestigationRecord) -> None:
        root = self.investigations_root / record.investigation_id
        root.mkdir(parents=True, exist_ok=True)
        self._write_json(root / "workflow.json", record)

    def _write_record(self, record: InvestigationRecord) -> None:
        if record.state is FindingState.INCIDENT and record.incident_id is not None:
            root = self.incidents_root / record.incident_id
            root.mkdir(parents=True, exist_ok=True)
            self._write_json(root / "workflow.json", record)
        elif record.state is FindingState.INVESTIGATING:
            self._write_investigation(record)

    @staticmethod
    def _write_json(path: Path, record: InvestigationRecord) -> None:
        payload = asdict(record)
        payload["state"] = record.state.value
        payload["created_at"] = record.created_at.isoformat()
        payload["updated_at"] = record.updated_at.isoformat()
        path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")

    @staticmethod
    def _read_json(path: Path) -> InvestigationRecord:
        payload: dict[str, object] = json.loads(path.read_text(encoding="utf-8"))
        return InvestigationRecord(
            investigation_id=str(payload["investigation_id"]),
            finding_id=str(payload["finding_id"]),
            source=str(payload["source"]),
            state=FindingState(str(payload["state"])),
            created_at=datetime.fromisoformat(str(payload["created_at"])),
            updated_at=datetime.fromisoformat(str(payload["updated_at"])),
            notes=tuple(str(item) for item in payload.get("notes", [])),
            incident_id=(
                str(payload["incident_id"]) if payload.get("incident_id") is not None else None
            ),
        )
