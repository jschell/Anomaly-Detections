import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import polars as pl
import pytest

from siem_anomaly import open_engagement
from siem_anomaly.core.domain import Finding
from siem_anomaly.persistence import ArtifactKind


def _finding() -> Finding:
    now = datetime.now(UTC)
    return Finding(
        finding_id="policy-finding",
        detector_id="identity.relationship_novelty",
        source="microsoft.entra_signin",
        start=now,
        end=now,
        score=1.0,
        entity="analyst@example.com",
    )


def test_policy_can_disable_investigating_evidence_but_allow_confirmed_incident(
    tmp_path: Path,
) -> None:
    root = tmp_path / "anomaly"
    initial = open_engagement(root)
    payload = json.loads(initial.paths.config.read_text(encoding="utf-8"))
    payload["evidence"]["investigating"]["enabled"] = False
    initial.paths.config.write_text(json.dumps(payload), encoding="utf-8")
    ctx = open_engagement(root)

    record = ctx.workflow.start(_finding(), investigation_id="INV-DISABLED")
    with pytest.raises(PermissionError):
        ctx.workflow.retain_selected_evidence(
            record,
            pl.DataFrame({"event": ["selected"]}),
            selection_reason="investigation evidence",
        )

    incident = ctx.workflow.promote(record, incident_id="INC-ALLOWED")
    retained = ctx.workflow.retain_selected_evidence(
        incident,
        pl.DataFrame({"event": ["selected"]}),
        selection_reason="confirmed incident evidence",
    )
    assert retained.exists()


def test_expired_investigation_cleanup_never_touches_incident(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    old = datetime.now(UTC) - timedelta(days=30)

    active = ctx.workflow.start(_finding(), investigation_id="INV-OLD")
    ctx.workflow.retain_selected_evidence(
        active,
        pl.DataFrame({"event": ["temporary"]}),
        selection_reason="temporary evidence",
    )
    workflow_path = ctx.paths.investigations / "INV-OLD" / "workflow.json"
    payload = json.loads(workflow_path.read_text(encoding="utf-8"))
    payload["updated_at"] = old.isoformat()
    workflow_path.write_text(json.dumps(payload), encoding="utf-8")

    confirmed = ctx.workflow.start(_finding(), investigation_id="INV-CONFIRMED")
    incident = ctx.workflow.promote(confirmed, incident_id="INC-PROTECTED")
    ctx.workflow.retain_selected_evidence(
        incident,
        pl.DataFrame({"event": ["incident"]}),
        selection_reason="confirmed evidence",
    )

    removed = ctx.workflow.cleanup_expired_investigations(now=datetime.now(UTC))
    assert removed == ("INV-OLD",)
    assert not (ctx.paths.investigations / "INV-OLD").exists()
    assert (ctx.paths.incidents / "INC-PROTECTED" / "events.parquet").exists()


def test_ordinary_raw_event_persistence_remains_non_configurable(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    with pytest.raises(PermissionError, match="Ordinary raw SIEM events"):
        ctx.policy.assert_allowed(ArtifactKind.RAW_EVENT)
