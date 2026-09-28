from __future__ import annotations

from dataclasses import dataclass, field

from siem_anomaly.adapters import EntraSigninAdapter, SourceAdapter


@dataclass(slots=True)
class AdapterRegistry:
    _adapters: dict[str, SourceAdapter] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self._adapters:
            self.register(EntraSigninAdapter())

    def register(self, adapter: SourceAdapter) -> None:
        self._adapters[adapter.source] = adapter

    def get(self, source: str) -> SourceAdapter:
        try:
            return self._adapters[source]
        except KeyError as exc:
            raise KeyError(f"No adapter registered for source {source!r}") from exc
