from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from siem_anomaly.adapters import SchemaProfile, SupportedFrame, to_polars
from siem_anomaly.core import CapabilityName, DetectorRequirement, DiscoveryResult, discover_compatible
from siem_anomaly.persistence import EngagementStore, PersistencePolicy
from siem_anomaly.registry import AdapterRegistry


_DEFAULT_REQUIREMENTS = (
    DetectorRequirement(
        "identity.actor_source_ip_first_seen",
        frozenset({CapabilityName.ACTOR, CapabilityName.SOURCE_IP}),
    ),
)


@dataclass(slots=True)
class EngagementContext:
    path: Path
    store: EngagementStore
    registry: AdapterRegistry

    def profile(self, frame: SupportedFrame, *, source: str) -> SchemaProfile:
        adapter = self.registry.get(source)
        df = to_polars(frame)
        return SchemaProfile(
            source=source,
            rows=df.height,
            columns=tuple(df.columns),
            capabilities=adapter.capabilities(df),
        )

    def discover(
        self,
        frame: SupportedFrame,
        *,
        source: str,
        requirements: tuple[DetectorRequirement, ...] | None = None,
    ) -> tuple[DiscoveryResult, ...]:
        profile = self.profile(frame, source=source)
        selected = requirements if requirements is not None else _DEFAULT_REQUIREMENTS
        return discover_compatible(profile.capabilities, selected)


def open_engagement(path: str | Path) -> EngagementContext:
    root = Path(path).expanduser().resolve()
    store = EngagementStore(root=root, policy=PersistencePolicy())
    store.initialize()
    return EngagementContext(path=root, store=store, registry=AdapterRegistry())
