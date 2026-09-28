from datetime import UTC, datetime, timedelta
from pathlib import Path

import polars as pl

from siem_anomaly import open_engagement
from siem_anomaly.provenance import CoverageWindow


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
    service_hour = ctx.features.read_feature("service_hour", feature_version="identity-v1")
    assert service_hour.height == 3
    actor_ip = ctx.features.read_state("actor_ip", feature_version="identity-v1")
    assert actor_ip.height == 1
    assert actor_ip["event_count"].item() == 6


def test_coverage_tracks_query_windows_and_empty_results(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    first_start = datetime(2026, 9, 1, tzinfo=UTC)
    first_end = datetime(2026, 9, 22, tzinfo=UTC)
    ctx.derive(
        _history(),
        source="microsoft.entra_signin",
        query_id="entra-history-2026-09-01_2026-09-22",
        feature_version="identity-v1",
        window_start=first_start,
        window_end=first_end,
    )

    empty = pl.DataFrame(
        schema={
            "TimeGenerated": pl.String,
            "UserPrincipalName": pl.String,
            "IPAddress": pl.String,
            "AppDisplayName": pl.String,
            "ResultType": pl.Int64,
        }
    )
    second_end = datetime(2026, 9, 28, tzinfo=UTC)
    ctx.derive(
        empty,
        source="microsoft.entra_signin",
        query_id="entra-history-2026-09-22_2026-09-28",
        feature_version="identity-v1",
        window_start=first_end,
        window_end=second_end,
    )

    assert ctx.coverage() == (CoverageWindow(first_start, second_end),)
    assert ctx.missing_windows(start=first_start, end=second_end) == ()

    completely_missing = ctx.missing_windows(
        start=first_start,
        end=second_end,
        feature_version="identity-v2",
    )
    assert completely_missing == (CoverageWindow(first_start, second_end),)


def test_repeated_query_id_replaces_same_feature_partition(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    for _ in range(2):
        ctx.derive(
            _history(),
            source="microsoft.entra_signin",
            query_id="stable-window-id",
        )
    assert len(list((ctx.paths.features / "actor_hour").rglob("*.parquet"))) == 1
    assert len(ctx.manifests.records(feature_set="identity", feature_version="identity-v1")) == 1


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
    assert "identity.relationship_change" in detector_ids
    assert "identity.rhythm_deviation" in detector_ids

    novelty = next(
        finding for finding in findings if finding.detector_id == "identity.relationship_novelty"
    )
    assert novelty.score == 1.0
    assert novelty.reason_codes == ("new_actor_source_ip",)
    assert "198.51.100.44" in novelty.reasons[0]
    assert novelty.query_context()["entity"] == "analyst@example.com"
    assert list(ctx.paths.findings.rglob("*.json"))


def test_conditional_rarity_is_separate_from_novelty(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    rare_history = pl.DataFrame(
        {
            "TimeGenerated": ["2026-09-21T09:00:00Z"],
            "UserPrincipalName": ["analyst@example.com"],
            "IPAddress": ["203.0.113.20"],
            "AppDisplayName": ["Azure Portal"],
            "ResultType": [0],
        }
    )
    ctx.derive(
        rare_history,
        source="microsoft.entra_signin",
        query_id="rare-ip-history",
    )

    current = pl.DataFrame(
        {
            "TimeGenerated": ["2026-09-28T09:00:00Z"],
            "UserPrincipalName": ["analyst@example.com"],
            "IPAddress": ["203.0.113.20"],
            "AppDisplayName": ["Azure Portal"],
            "ResultType": [0],
        }
    )
    findings = ctx.detect(current, source="microsoft.entra_signin", persist=False)
    rarity = next(f for f in findings if f.detector_id == "identity.conditional_rarity")
    assert rarity.reason_codes == ("rare_actor_source_ip",)
    assert not any(f.detector_id == "identity.relationship_novelty" for f in findings)


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
    volume = next(f for f in findings if f.detector_id == "identity.volume_deviation")
    assert volume.reason_codes == ("actor_hour_volume_above_p95",)
    robust = next(
        f for f in findings if f.detector_id == "identity.robust_historical_deviation"
    )
    assert robust.reason_codes == ("actor_hour_robust_deviation",)
    organization = next(
        f for f in findings if f.detector_id == "identity.organization_relative_deviation"
    )
    assert organization.reason_codes == ("actor_volume_above_organization_p95",)
