import json
from datetime import UTC, datetime
from pathlib import Path

from siem_anomaly.evaluation import IncidentDefinition, ReplayMetrics, ReplayReport
from siem_anomaly.feature_catalog import PortabilityExpectation
from siem_anomaly.portability import (
    EnvironmentFeatureMetrics,
    assess_portability,
    export_approved_summaries,
    leave_one_environment_out,
    summarize_replay_feature,
)


def _summaries() -> tuple[EnvironmentFeatureMetrics, ...]:
    return (
        EnvironmentFeatureMetrics(
            "env-a",
            "identity.actor_source_ip.rarity_score",
            2.1,
            0.90,
            0.70,
            0.05,
            4.0,
            3.0,
            True,
        ),
        EnvironmentFeatureMetrics(
            "env-b",
            "identity.actor_source_ip.rarity_score",
            1.8,
            0.80,
            0.65,
            0.08,
            2.0,
            2.0,
            True,
        ),
        EnvironmentFeatureMetrics(
            "env-c",
            "identity.actor_source_ip.rarity_score",
            2.4,
            0.75,
            0.60,
            0.09,
            3.0,
            1.0,
            False,
        ),
    )


def test_portability_assessment_and_leave_one_environment_out() -> None:
    summaries = _summaries()
    assessment = assess_portability(
        summaries,
        feature_id="identity.actor_source_ip.rarity_score",
    )
    assert assessment.environments_tested == 3
    assert assessment.evidence is PortabilityExpectation.HIGH

    loo = leave_one_environment_out(
        summaries,
        feature_id="identity.actor_source_ip.rarity_score",
    )
    assert len(loo) == 3
    assert all(result.generalizes for result in loo)


def test_only_approved_metrics_summaries_are_exported(tmp_path: Path) -> None:
    destination = export_approved_summaries(_summaries(), tmp_path / "portable.json")
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert len(payload) == 2
    assert {item["environment_id"] for item in payload} == {"env-a", "env-b"}
    assert all("feature_id" in item for item in payload)


def test_replay_report_converts_to_metrics_only_feature_summary() -> None:
    incident = IncidentDefinition(
        incident_id="IR-PORT-1",
        source="microsoft.entra_signin",
        start=datetime(2026, 9, 28, 3, tzinfo=UTC),
        end=datetime(2026, 9, 28, 4, tzinfo=UTC),
        entities=("victim@example.com",),
    )
    report = ReplayReport(
        incident=incident,
        metrics=ReplayMetrics(
            incident_rank=2,
            precision_at_10=0.5,
            precision_at_25=0.4,
            precision_at_50=0.3,
            recall_at_10=1.0,
            recall_at_25=1.0,
            recall_at_50=1.0,
            false_positives=4,
            time_to_first_signal_seconds=60.0,
        ),
        detector_contribution={"identity.relationship_novelty": 1},
        false_positives_by_detector={"identity.rhythm_deviation": 4},
        false_positives_by_entity={"control@example.com": 4},
        effect_sizes={"unique_ips": 2.2},
        ablation_rank_without_detector={"identity.relationship_novelty": 5},
        finding_count=10,
    )
    summary = summarize_replay_feature(
        report,
        environment_id="env-a",
        feature_id="identity.actor_hour.unique_ips",
        effect_key="unique_ips",
        rank_contribution=3.0,
        ablation_delta=3.0,
        approved_for_export=True,
    )
    assert summary.effect_size == 2.2
    assert summary.incident_recall == 1.0
    assert summary.precision_at_25 == 0.4
    assert summary.false_positive_rate == 0.4
