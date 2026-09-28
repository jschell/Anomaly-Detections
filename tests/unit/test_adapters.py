import polars as pl

from siem_anomaly.adapters.base import MappingAdapter
from siem_anomaly.adapters.microsoft import ENTRA_SIGNIN_ADAPTER
from siem_anomaly.core.capabilities import Capability, FieldBinding


def test_entra_signin_profiles_capabilities() -> None:
    frame = pl.DataFrame(
        {
            "TimeGenerated": ["2026-09-28T12:00:00Z", "2026-09-28T13:00:00Z"],
            "UserPrincipalName": ["analyst@example.com", "analyst@example.com"],
            "IPAddress": ["192.0.2.10", None],
            "AppDisplayName": ["Azure Portal", "Azure Portal"],
            "ResultType": [0, 0],
        }
    )
    profile = ENTRA_SIGNIN_ADAPTER.profile(frame)
    assert profile.missing_required_fields == ()
    assert Capability.ACTOR in profile.capabilities
    assert Capability.SOURCE_IP in profile.capabilities

    source_ip_coverage = next(
        item for item in profile.capability_coverage if item.capability is Capability.SOURCE_IP
    )
    assert source_ip_coverage.semantic_role == "client_origin"
    assert source_ip_coverage.completeness == 0.5

    normalized = ENTRA_SIGNIN_ADAPTER.normalize(frame)
    assert normalized.columns == ["timestamp", "actor", "source_ip", "application", "outcome"]


def test_entra_signin_supports_field_overrides() -> None:
    adapter = ENTRA_SIGNIN_ADAPTER.with_overrides(
        {"actor": "AccountUPN", "source_ip": "ClientIP"}
    )
    frame = pl.DataFrame(
        {
            "TimeGenerated": ["2026-09-28T12:00:00Z"],
            "AccountUPN": ["analyst@example.com"],
            "ClientIP": ["192.0.2.10"],
        }
    )
    normalized = adapter.normalize(frame)
    assert normalized.columns == ["timestamp", "actor", "source_ip"]


def test_generic_mapping_adapter_uses_same_capability_logic() -> None:
    adapter = MappingAdapter(
        source_id="example.auth",
        bindings=(
            FieldBinding("timestamp", "ts", Capability.TIMESTAMP, "event_time", True),
            FieldBinding(
                "actor",
                "principal",
                Capability.ACTOR,
                "authenticated_principal",
                True,
            ),
            FieldBinding("source_ip", "client_ip", Capability.SOURCE_IP, "client_origin"),
        ),
    )
    frame = pl.DataFrame({"ts": ["now"], "principal": ["u"], "client_ip": ["1.2.3.4"]})
    profile = adapter.profile(frame)
    assert {Capability.TIMESTAMP, Capability.ACTOR, Capability.SOURCE_IP} <= profile.capabilities
