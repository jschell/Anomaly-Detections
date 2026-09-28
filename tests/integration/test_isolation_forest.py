from datetime import UTC, datetime, timedelta
from pathlib import Path

import polars as pl

from siem_anomaly import open_engagement
from siem_anomaly.models import compare_model_to_deterministic
from siem_anomaly.models.time_series import random_cut_forest_decision


def _training_events() -> pl.DataFrame:
    base = datetime(2026, 9, 1, 9, tzinfo=UTC)
    times: list[str] = []
    actors: list[str] = []
    ips: list[str] = []
    apps: list[str] = []
    outcomes: list[int] = []
    for day in range(20):
        for actor_index in range(4):
            count = 2 + (actor_index % 2)
            for event_index in range(count):
                stamp = base + timedelta(days=day, minutes=event_index)
                times.append(stamp.isoformat().replace("+00:00", "Z"))
                actors.append(f"user{actor_index}@example.com")
                ips.append(f"192.0.2.{actor_index + 1}")
                apps.append("Azure Portal")
                outcomes.append(0)
    return pl.DataFrame(
        {
            "TimeGenerated": times,
            "UserPrincipalName": actors,
            "IPAddress": ips,
            "AppDisplayName": apps,
            "ResultType": outcomes,
        }
    )


def test_isolation_forest_is_versioned_scored_and_gated_by_incremental_value(
    tmp_path: Path,
) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    training = _training_events()
    ctx.derive(
        training,
        source="microsoft.entra_signin",
        query_id="training-window",
    )

    artifact = ctx.train_isolation_forest(
        model_id="iforest-v1",
        contamination=0.05,
    )
    assert artifact.model_path.exists()
    assert artifact.metadata_path.exists()

    anomaly_time = datetime(2026, 9, 28, 9, tzinfo=UTC)
    current = pl.DataFrame(
        {
            "TimeGenerated": [
                (anomaly_time + timedelta(minutes=i)).isoformat().replace("+00:00", "Z")
                for i in range(25)
            ]
            + ["2026-09-28T09:00:00Z"],
            "UserPrincipalName": ["incident@example.com"] * 25 + ["user1@example.com"],
            "IPAddress": ["198.51.100.9"] * 25 + ["192.0.2.2"],
            "AppDisplayName": ["Azure Portal"] * 26,
            "ResultType": [0] * 26,
        }
    )
    scores = ctx.score_isolation_forest(
        current,
        source="microsoft.entra_signin",
        artifact=artifact,
    )
    assert {
        "iforest_score_samples",
        "iforest_decision_function",
        "anomaly_score",
        "model_flag",
    } <= set(scores.columns)

    comparison = compare_model_to_deterministic(
        scores,
        incident_entities=("incident@example.com",),
        incident_start=anomaly_time,
        incident_end=anomaly_time + timedelta(hours=1),
        deterministic_rank=3,
        deterministic_precision_at_n=0.0,
        n=10,
    )
    assert comparison.model_rank is not None
    assert comparison.retained
    assert (
        random_cut_forest_decision(isolation_forest_retained=comparison.retained).status
        == "candidate"
    )


def test_model_escalation_stops_without_incremental_value() -> None:
    decision = random_cut_forest_decision(isolation_forest_retained=False)
    assert decision.status == "deferred"
