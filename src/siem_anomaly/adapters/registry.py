"""Built-in provider adapter registry."""

from siem_anomaly.adapters.base import SourceAdapter
from siem_anomaly.adapters.microsoft import ENTRA_SIGNIN_ADAPTER

_BUILTINS: dict[str, SourceAdapter] = {
    ENTRA_SIGNIN_ADAPTER.source_id: ENTRA_SIGNIN_ADAPTER,
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
