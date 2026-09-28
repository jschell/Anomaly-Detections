"""Built-in provider adapter registry."""

from siem_anomaly.adapters.aws import AWS_CLOUDTRAIL_ADAPTER
from siem_anomaly.adapters.base import SourceAdapter
from siem_anomaly.adapters.gcp import GCP_AUDIT_LOG_ADAPTER
from siem_anomaly.adapters.microsoft import (
    AZURE_ACTIVITY_ADAPTER,
    ENTRA_AUDIT_ADAPTER,
    ENTRA_SIGNIN_ADAPTER,
    M365_AUDIT_ADAPTER,
)
from siem_anomaly.adapters.okta import OKTA_SYSTEM_LOG_ADAPTER

_BUILTINS: dict[str, SourceAdapter] = {
    adapter.source_id: adapter
    for adapter in (
        ENTRA_SIGNIN_ADAPTER,
        ENTRA_AUDIT_ADAPTER,
        AZURE_ACTIVITY_ADAPTER,
        M365_AUDIT_ADAPTER,
        OKTA_SYSTEM_LOG_ADAPTER,
        AWS_CLOUDTRAIL_ADAPTER,
        GCP_AUDIT_LOG_ADAPTER,
    )
}


def get_adapter(source: str) -> SourceAdapter:
    try:
        return _BUILTINS[source]
    except KeyError as exc:
        raise KeyError(f"Unknown source adapter: {source}") from exc


def register_adapter(adapter: SourceAdapter) -> None:
    if adapter.source_id in _BUILTINS:
        raise ValueError(f"Adapter already registered: {adapter.source_id}")
    _BUILTINS[adapter.source_id] = adapter


def registered_sources() -> tuple[str, ...]:
    return tuple(sorted(_BUILTINS))
