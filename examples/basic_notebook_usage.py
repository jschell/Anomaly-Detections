from pathlib import Path

import polars as pl

import siem_anomaly as sa

frame = pl.DataFrame(
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

ctx = sa.open_engagement(Path("./engagement/anomaly"))
print(ctx.profile(frame, source="microsoft.entra_signin"))
