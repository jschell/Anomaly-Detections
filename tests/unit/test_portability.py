import json
from pathlib import Path

from siem_anomaly.feature_catalog import PortabilityExpectation
from siem_anomaly.portability import (
    EnvironmentFeatureMetrics,
    assess_portability,
    export_approved_summaries,
    leave_one_environment_out,
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
