import polars as pl

from siem_anomaly.adapters.microsoft import EntraSigninAdapter
from siem_anomaly.core import CapabilityName


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


def test_entra_adapter_normalizes_canonical_fields() -> None:
    adapter = EntraSigninAdapter()
    normalized = adapter.normalize(_frame())

    assert normalized.columns == [
        "timestamp",
        "actor",
        "source_ip",
        "application",
        "country",
        "outcome",
        "device",
    ]


def test_entra_adapter_reports_semantic_capabilities() -> None:
    adapter = EntraSigninAdapter()
    capabilities = adapter.capabilities(_frame())
    names = {capability.name for capability in capabilities}

    assert CapabilityName.ACTOR in names
    assert CapabilityName.SOURCE_IP in names
    assert CapabilityName.APPLICATION in names
