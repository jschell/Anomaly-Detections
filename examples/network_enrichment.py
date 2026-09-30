"""Run with `uv run python examples/network_enrichment.py`. Synthetic values only."""

from datetime import UTC, datetime, timedelta
from tempfile import TemporaryDirectory

import polars as pl

import siem_anomaly as sa


def events(days: list[int], asns: list[str], traits: list[str]) -> pl.DataFrame:
    start = datetime(2026, 1, 1, 10, tzinfo=UTC)
    return pl.DataFrame(
        {
            "TimeGenerated": [(start + timedelta(days=day)).isoformat() for day in days],
            "UserPrincipalName": ["sample@example.test"] * len(days),
            "IPAddress": ["192.0.2.10"] * len(days),
            "enriched_asn": asns,
            "enriched_traits": traits,
        }
    )


fields = {"asn": "enriched_asn", "network_trait": "enriched_traits"}
with TemporaryDirectory() as workspace:
    ctx = sa.open_engagement(workspace)
    ctx.derive(
        events([0, 7, 14], ["AS64500"] * 3, ["cdn"] * 3),
        source="microsoft.entra_signin",
        query_id="synthetic-history",
        enrichment_fields=fields,
        enrichment_source="synthetic_fixture",
        enrichment_version="1",
        window_start=datetime(2026, 1, 1, 10, tzinfo=UTC),
        window_end=datetime(2026, 1, 22, 10, tzinfo=UTC),
    )
    findings = ctx.detect(
        events([21], ["AS64501"], ["proxy"]),
        source="microsoft.entra_signin",
        enrichment_fields=fields,
        enrichment_source="synthetic_fixture",
        enrichment_version="1",
        persist=False,
    )
    for finding in findings:
        print(finding.detector_id, finding.reasons)
