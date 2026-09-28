from datetime import UTC, datetime
from pathlib import Path

import polars as pl

from siem_anomaly import open_engagement
from siem_anomaly.core.domain import Finding
from siem_anomaly.workflow import FindingState


def _finding() -> Finding:
    return Finding(
        finding_id="finding-1",
        detector_id="identity.relationship_novelty",
        source="microsoft.entra_signin",
        start=datetime(2026, 9, 28, 3, tzinfo=UTC),
        end=datetime(2026, 9, 28, 3, 5, tzinfo=UTC),
        score=1.0,
        entity="victim@example.com",
        reason_codes=("new_actor_source_ip",),
        reasons=("new IP",),
    )


def test_investigation_can_retain_promote_and_preserve_evidence_manifest(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    finding = _finding()
    record = ctx.workflow.start(finding, investigation_id="INV-001", note="reviewed")

    evidence = ctx.workflow.retain_selected_evidence(
        record,
        pl.DataFrame({"TimeGenerated": ["2026-09-28T03:00:00Z"], "detail": ["selected"]}),
        selection_reason="directly supports the suspicious sign-in finding",
    )
    assert evidence.exists()
    assert (evidence.parent / "events.parquet.manifest.json").exists()

    incident = ctx.workflow.promote(record, incident_id="INC-001", note="confirmed")
    assert incident.state is FindingState.INCIDENT
    assert not (ctx.paths.investigations / "INV-001").exists()
    assert (ctx.paths.incidents / "INC-001" / "events.parquet").exists()
    assert ctx.workflow.load("INV-001").state is FindingState.INCIDENT


def test_dismissal_removes_temporary_evidence_but_keeps_disposition(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    record = ctx.workflow.start(_finding(), investigation_id="INV-002")
    ctx.workflow.retain_selected_evidence(
        record,
        pl.DataFrame({"event": ["temporary"]}),
        selection_reason="temporary investigation evidence",
    )

    dismissed = ctx.workflow.dismiss(record, note="benign")
    assert dismissed.state is FindingState.DISMISSED
    assert not (ctx.paths.investigations / "INV-002").exists()
    assert (ctx.paths.investigations / "_dismissed" / "INV-002.json").exists()
