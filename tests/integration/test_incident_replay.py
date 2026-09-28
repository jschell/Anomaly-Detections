from datetime import UTC, datetime
from pathlib import Path

import polars as pl

from siem_anomaly import open_engagement
from siem_anomaly.evaluation import IncidentDefinition


def _baseline() -> pl.DataFrame:
    return pl.DataFrame(
        {
            "TimeGenerated": [
                "2026-09-20T09:00:00Z",
                "2026-09-21T09:00:00Z",
                "2026-09-22T09:00:00Z",
                "2026-09-20T09:00:00Z",
                "2026-09-21T09:00:00Z",
                "2026-09-22T09:00:00Z",
            ],
            "UserPrincipalName": [
                "victim@example.com",
                "victim@example.com",
                "victim@example.com",
                "control@example.com",
                "control@example.com",
                "control@example.com",
            ],
            "IPAddress": [
                "192.0.2.10",
                "192.0.2.10",
                "192.0.2.10",
                "192.0.2.20",
                "192.0.2.20",
                "192.0.2.20",
            ],
            "AppDisplayName": ["Azure Portal"] * 6,
            "ResultType": [0] * 6,
        }
    )


def _replay() -> pl.DataFrame:
    return pl.DataFrame(
        {
            "TimeGenerated": [
                "2026-09-28T03:00:00Z",
                "2026-09-28T09:00:00Z",
            ],
            "UserPrincipalName": ["victim@example.com", "control@example.com"],
            "IPAddress": ["198.51.100.77", "192.0.2.20"],
            "AppDisplayName": ["Azure Portal", "Azure Portal"],
            "ResultType": [0, 0],
        }
    )


def test_known_incident_replay_reports_rank_lead_time_and_ablation(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    incident = IncidentDefinition(
        incident_id="IR-001",
        source="microsoft.entra_signin",
        start=datetime(2026, 9, 28, 3, tzinfo=UTC),
        end=datetime(2026, 9, 28, 4, tzinfo=UTC),
        entities=("victim@example.com",),
    )

    report = ctx.replay(
        baseline_data=_baseline(),
        replay_data=_replay(),
        incident=incident,
    )

    assert report.metrics.incident_rank is not None
    assert report.metrics.recall_at_10 == 1.0
    assert report.metrics.time_to_first_signal_seconds == 0.0
    assert report.detector_contribution
    assert report.ablation_rank_without_detector
    assert (ctx.paths.evaluation / "replays" / "IR-001.json").exists()
    assert not (ctx.root / "raw").exists()
