"""Minimal notebook-style integration example."""

from pathlib import Path

import polars as pl

import siem_anomaly as sa

engagement = sa.open_engagement(Path("./example-engagement/anomaly"))

frame = pl.DataFrame(
    {
        "TimeGenerated": ["2026-09-28T12:00:00Z"],
        "UserPrincipalName": ["analyst@example.com"],
        "IPAddress": ["192.0.2.10"],
        "AppDisplayName": ["Azure Portal"],
        "ResultType": [0],
    }
)

profile = engagement.profile(frame, source="microsoft.entra_signin")
print(profile)
