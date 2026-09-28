from pathlib import Path

import polars as pl
import pytest

import siem_anomaly as sa
from siem_anomaly.core import CapabilityName, DetectorRequirement
from siem_anomaly.persistence import ArtifactType


def _frame() -> pl.DataFrame:
    return pl.DataFrame(
        {
            "TimeGenerated": ["2026-09-28T00:00:00Z"],
            "UserPrincipalName": ["alice@example.com"],
            "IPAddress": ["203.0.113.4"],
            "AppDisplayName": ["Azure Portal"],
            "Location": ["US"],
            "ResultType": ["0"],
            "DeviceDetail": ["managed"],
        }
    )


def test_open_engagement_creates_isolated_storage_and_profiles(tmp_path: Path) -> None:
    ctx = sa.open_engagement(tmp_path / "anomaly")
    profile = ctx.profile(_frame(), source="microsoft.entra_signin")

    assert profile.rows == 1
    assert (ctx.path / "features").is_dir()
    assert (ctx.path / "incidents").is_dir()


def test_capability_discovery_from_entra_source(tmp_path: Path) -> None:
    ctx = sa.open_engagement(tmp_path / "anomaly")
    requirement = DetectorRequirement(
        "generic.actor_ip",
        frozenset({CapabilityName.ACTOR, CapabilityName.SOURCE_IP}),
    )
    results = ctx.discover(
        _frame(),
        source="microsoft.entra_signin",
        requirements=(requirement,),
    )
    assert results[0].compatible is True


def test_raw_incident_evidence_requires_explicit_promotion(tmp_path: Path) -> None:
    ctx = sa.open_engagement(tmp_path / "anomaly")

    with pytest.raises(PermissionError, match="explicit promotion"):
        ctx.store.write_parquet(
            ArtifactType.INCIDENT_EVIDENCE,
            "INC-001/events.parquet",
            _frame(),
        )

    path = ctx.store.write_parquet(
        ArtifactType.INCIDENT_EVIDENCE,
        "INC-001/events.parquet",
        _frame(),
        explicit_incident_promotion=True,
    )
    assert path.exists()
