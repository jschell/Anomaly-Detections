"""Synthetic integration coverage for optional network enrichment."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import polars as pl
import pytest

from siem_anomaly import open_engagement
from siem_anomaly.core.network import asn_value, trait_value
from siem_anomaly.evaluation import IncidentDefinition

FIELDS = {"asn": "enriched_asn", "network_trait": "enriched_traits"}


def _frame(days: list[int], asns: list[object], traits: list[object]) -> pl.DataFrame:
    base = datetime(2026, 1, 1, 10, tzinfo=UTC)
    return pl.DataFrame(
        {
            "TimeGenerated": [(base + timedelta(days=day)).isoformat() for day in days],
            "UserPrincipalName": ["actor@example.test"] * len(days),
            "IPAddress": ["192.0.2.1"] * len(days),
            "enriched_asn": asns,
            "enriched_traits": traits,
        },
        strict=False,
    )


def test_network_values_are_validated_and_profiled(tmp_path: Path) -> None:
    assert asn_value("AS64500") == "64500"
    assert asn_value(0) is None
    assert asn_value("AS99999999999") is None
    assert trait_value("VPN|cdn|unknown") == "cdn,vpn"
    ctx = open_engagement(tmp_path)
    frame = _frame([0, 1], ["AS64500", "garbage"], ["proxy", "unknown"])
    profile = ctx.profile(frame, source="microsoft.entra_signin", enrichment_fields=FIELDS)
    coverage = {item.canonical_name: item.completeness for item in profile.capability_coverage}
    assert coverage["asn"] == 0.5
    assert coverage["network_trait"] == 0.5
    assert "identity.asn_change" not in ctx.discover(
        frame,
        source="microsoft.entra_signin",
        enrichment_fields=FIELDS,
        enrichment_source="test_dataset",
        enrichment_version="1",
    )
    invalid = _frame([0], ["garbage"], ["unknown"])
    assert not any(
        item.startswith("identity.asn_") or item == "identity.network_trait_novelty"
        for item in ctx.discover(
            invalid,
            source="microsoft.entra_signin",
            enrichment_fields=FIELDS,
            enrichment_source="test_dataset",
            enrichment_version="1",
        )
    )
    native = frame.rename({"enriched_asn": "AutonomousSystemNumber"})
    native_profile = ctx.profile(native, source="microsoft.entra_signin")
    assert any(item.canonical_name == "asn" for item in native_profile.capability_coverage)


def test_versioned_derived_state_and_eligible_findings(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path)
    baseline = _frame([0, 7, 14], [64500] * 3, ["residential"] * 3)
    # Unsupported classes are unknown, so use one recognized historical class.
    baseline = baseline.with_columns(pl.lit("cdn").alias("enriched_traits"))
    for _ in range(2):
        ctx.derive(
            baseline,
            source="microsoft.entra_signin",
            query_id="baseline",
            enrichment_fields=FIELDS,
            enrichment_source="test_dataset",
            enrichment_version="1",
            window_start=datetime(2026, 1, 1, tzinfo=UTC),
            window_end=datetime(2026, 1, 22, 10, tzinfo=UTC),
        )
    records = ctx.manifests.records(feature_version="identity-network-v1")
    assert len(records) == 1
    assert records[0].capability_coverage["asn"] == 1.0
    assert ctx.features.read_state("actor_asn", feature_version="identity-network-v1").height == 1
    assert ctx.features.read_state("actor_asn", feature_version="identity-v1").is_empty()
    assert not (tmp_path / "raw").exists()

    current = _frame([21, 21, 21], [64501, 64502, 64503], ["proxy"] * 3)
    findings = ctx.detect(
        current,
        source="microsoft.entra_signin",
        enrichment_fields=FIELDS,
        enrichment_source="test_dataset",
        enrichment_version="1",
        persist=False,
    )
    ids = {finding.detector_id for finding in findings}
    assert "identity.asn_change" in ctx.discover(
        current,
        source="microsoft.entra_signin",
        enrichment_fields=FIELDS,
        enrichment_source="test_dataset",
        enrichment_version="1",
    )
    assert "identity.asn_change" in ids
    assert "identity.network_trait_novelty" in ids
    assert "identity.asn_diversity" in ids
    assert "identity.asn_novelty" not in ids

    with pytest.raises(ValueError, match="provenance changed"):
        ctx.detect(
            current,
            source="microsoft.entra_signin",
            enrichment_fields=FIELDS,
            enrichment_source="test_dataset",
            enrichment_version="2",
            persist=False,
        )
    with pytest.raises(ValueError, match="source-scoped"):
        ctx.derive(
            _frame([21], [64501], ["proxy"]).rename(
                {"TimeGenerated": "published", "UserPrincipalName": "actor.alternateId"}
            ),
            source="okta.system_log",
            query_id="other-source",
            enrichment_fields=FIELDS,
            enrichment_source="test_dataset",
            enrichment_version="1",
        )
    with pytest.raises(ValueError, match="new feature version"):
        ctx.detect(
            current,
            source="microsoft.entra_signin",
            feature_version="identity-v1",
            enrichment_fields=FIELDS,
            enrichment_source="test_dataset",
            enrichment_version="1",
            persist=False,
        )


def test_future_state_does_not_create_network_baseline(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path)
    ctx.derive(
        _frame([20, 27, 34], [64500] * 3, ["cdn"] * 3),
        source="microsoft.entra_signin",
        query_id="future",
        enrichment_fields=FIELDS,
        enrichment_source="test_dataset",
        enrichment_version="1",
    )
    findings = ctx.detect(
        _frame([10], [64501], ["proxy"]),
        source="microsoft.entra_signin",
        enrichment_fields=FIELDS,
        enrichment_source="test_dataset",
        enrichment_version="1",
        persist=False,
    )
    assert not any(f.detector_id.startswith("identity.asn_") for f in findings)
    assert not any(f.detector_id == "identity.network_trait_novelty" for f in findings)


def test_incomplete_enrichment_coverage_suppresses_network_findings(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path)
    ctx.derive(
        _frame([0, 7, 14], [64500] * 3, ["cdn"] * 3),
        source="microsoft.entra_signin",
        query_id="sparse-history",
        enrichment_fields=FIELDS,
        enrichment_source="test_dataset",
        enrichment_version="1",
    )
    findings = ctx.detect(
        _frame([21], [64501], ["proxy"]),
        source="microsoft.entra_signin",
        enrichment_fields=FIELDS,
        enrichment_source="test_dataset",
        enrichment_version="1",
        persist=False,
    )
    assert not any(f.detector_id.startswith("identity.asn_") for f in findings)
    assert not any(f.detector_id == "identity.network_trait_novelty" for f in findings)


def test_partial_field_coverage_does_not_claim_novelty(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path)
    ctx.derive(
        _frame([0, 7, 14], [64500, None, 64500], ["cdn"] * 3),
        source="microsoft.entra_signin",
        query_id="partial",
        enrichment_fields=FIELDS,
        enrichment_source="test_dataset",
        enrichment_version="1",
        window_start=datetime(2026, 1, 1, 10, tzinfo=UTC),
        window_end=datetime(2026, 1, 22, 10, tzinfo=UTC),
    )
    current = _frame([21], [64501], ["cdn"])
    available = ctx.discover(
        current,
        source="microsoft.entra_signin",
        enrichment_fields=FIELDS,
        enrichment_source="test_dataset",
        enrichment_version="1",
    )
    assert "identity.asn_change" not in available
    assert "identity.network_trait_novelty" in available


def test_asn_novelty_is_distinct_from_stable_actor_change(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path)
    ctx.derive(
        _frame([0, 7, 14], [64500, 64501, 64500], ["cdn"] * 3),
        source="microsoft.entra_signin",
        query_id="multiple-asns",
        enrichment_fields=FIELDS,
        enrichment_source="test_dataset",
        enrichment_version="1",
        window_start=datetime(2026, 1, 1, 10, tzinfo=UTC),
        window_end=datetime(2026, 1, 22, 10, tzinfo=UTC),
    )
    findings = ctx.detect(
        _frame([21], [64502], ["cdn"]),
        source="microsoft.entra_signin",
        enrichment_fields=FIELDS,
        enrichment_source="test_dataset",
        enrichment_version="1",
        persist=False,
    )
    ids = {finding.detector_id for finding in findings}
    assert "identity.asn_novelty" in ids
    assert "identity.asn_change" not in ids


def test_replay_reports_network_contribution_and_ablation(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path)
    baseline = _frame([0, 7, 14], [64500] * 3, ["cdn"] * 3)
    current = _frame([21], [64501], ["proxy"])
    incident_start = datetime(2026, 1, 22, 10, tzinfo=UTC)
    incident = IncidentDefinition(
        incident_id="synthetic-network",
        source="microsoft.entra_signin",
        start=incident_start,
        end=incident_start + timedelta(hours=1),
        entities=("actor@example.test",),
    )
    report = ctx.replay(
        baseline_data=baseline,
        replay_data=current,
        incident=incident,
        feature_version="identity-network-v1",
        enrichment_fields=FIELDS,
        enrichment_source="synthetic_fixture",
        enrichment_version="1",
    )
    assert report.detector_contribution["identity.asn_change"] == 1
    assert report.ablation_rank_without_detector["identity.asn_change"] is not None
    assert report.false_positives_by_detector.get("identity.asn_change", 0) == 0
    assert report.enrichment_version == "1"
    assert report.metrics.incident_rank is not None
    assert report.metrics.false_positives == 0
