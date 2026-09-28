from pathlib import Path

import polars as pl

from siem_anomaly import open_engagement


def test_engagement_initializes_only_derived_storage(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    assert ctx.paths.features.is_dir()
    assert ctx.paths.state.is_dir()
    assert ctx.paths.incidents.is_dir()
    assert not (ctx.root / "raw").exists()
    assert not (ctx.root / "events").exists()


def test_incident_evidence_promotion_is_explicit(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    saved = ctx.incidents.promote("INC-001", pl.DataFrame({"event": ["selected"]}))
    assert saved.exists()
    assert saved.parent.name == "INC-001"
