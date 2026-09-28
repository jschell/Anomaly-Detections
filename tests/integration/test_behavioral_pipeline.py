from datetime import UTC, datetime, timedelta
from pathlib import Path

import polars as pl

from siem_anomaly import open_engagement


def _history() -> pl.DataFrame:
    return pl.DataFrame(
        {
            "TimeGenerated": [
                "2026-09-07T09:00:00Z",
                "2026-09-07T09:10:00Z",
                "2026-09-14T09:00:00Z",
                "2026-09-14T09:10:00Z",
                "2026-09-21T09:00:00Z",
                "2026-09-21T09:10:00Z",
            ],
            "UserPrincipalName": ["analyst@example.com"] * 6,
            "IPAddress": ["192.0.2.10"] * 6,
            "AppDisplayName": ["Azure Portal"] * 6,
            "ResultType": [0] * 6,
        }
    )


def test_derive_persists_only_behavioral_state_and_provenance(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    manifest = ctx.derive(
        _history(),
        source="microsoft.entra_signin",
        query_id="entra-history-2026-09",
    )

    assert manifest.source_rows == 6
    assert manifest.derived_rows > 0
    assert list(ctx.paths.features.rglob("*.parquet"))
    assert list(ctx.paths.state.rglob("*.parquet"))
    assert list(ctx.paths.manifests.glob("*.json"))
    assert not (ctx.root / "raw").exists()
    assert not (ctx.root / "events").exists()

    actor_hour = ctx.features.read_feature("actor_hour", feature_version="identity-v1")
    assert actor_hour.height == 3
    actor_ip = ctx.features.read_state("actor_ip", feature_version="identity-v1")
    assert actor_ip.height == 1
    assert actor_ip["event_count"].item() == 6


def test_coverage_and_missing_windows_support_backfill(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    ctx.derive(
        _history(),
        source="microsoft.entra_signin",
        query_id="entra-history-2026-09",
        feature_version="identity-v1",
    )

    coverage = ctx.coverage()
    assert len(coverage) == 1
    requested_start = datetime(2026, 9, 1, tzinfo=UTC)
    requested_end = datetime(2026, 9, 28, tzinfo=UTC)
    missing = ctx.missing_windows(start=requested_start, end=requested_end)
    assert len(missing) == 2
    assert missing[0].start == requested_start
    assert missing[-1].end == requested_end

    completely_missing = ctx.missing_windows(
        start=requested_start,
        end=requested_end,
        feature_version="identity-v2",
    )
    assert completely_missing == ((type(completely_missing[0]))(requested_start, requested_end),)


def test_rebuild_rhythm_and_detect_explainable_findings(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    ctx.derive(
        _history(),
        source="microsoft.entra_signin",
        query_id="entra-history-2026-09",
    )
    actor_rhythm, environment_rhythm = ctx.rebuild_baselines()
    assert actor_rhythm.height == 1
    assert environment_rhythm.height == 1

    current = pl.DataFrame(
        {
            "TimeGenerated": ["2026-09-28T03:00:00Z"],
            "UserPrincipalName": ["analyst@example.com"],
            "IPAddress": ["198.51.100.44"],
            "AppDisplayName": ["Azure Portal"],
            "ResultType": [0],
        }
    )
    available = ctx.discover(current, source="microsoft.entra_signin")
    assert "identity.relationship_novelty" in available
    assert "identity.rhythm_deviation" in available

    findings = ctx.detect(current, source="microsoft.entra_signin", persist=True)
    detector_ids = {finding.detector_id for finding in findings}
    assert "identity.relationship_novelty" in detector_ids
    assert "identity.rhythm_deviation" in detector_ids

    novelty = next(
        finding for finding in findings if finding.detector_id == "identity.relationship_novelty"
    )
    assert novelty.score == 1.0
    assert "198.51.100.44" in novelty.reasons[0]
    assert novelty.query_context()["entity"] == "analyst@example.com"
    assert list(ctx.paths.findings.rglob("*.json"))


def test_volume_deviation_uses_historical_actor_hour_baseline(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    ctx.derive(
        _history(),
        source="microsoft.entra_signin",
        query_id="entra-history-2026-09",
    )

    base = datetime(2026, 9, 28, 9, tzinfo=UTC)
    current = pl.DataFrame(
        {
            "TimeGenerated": [
                (base + timedelta(minutes=i)).isoformat().replace("+00:00", "Z") for i in range(10)
            ],
            "UserPrincipalName": ["analyst@example.com"] * 10,
            "IPAddress": ["192.0.2.10"] * 10,
            "AppDisplayName": ["Azure Portal"] * 10,
            "ResultType": [0] * 10,
        }
    )
    findings = ctx.detect(current, source="microsoft.entra_signin", persist=False)
    assert any(f.detector_id == "identity.volume_deviation" for f in findings)
