"""Engagement-scoped entry point for analysis state."""

from dataclasses import dataclass
from pathlib import Path

import polars as pl

from siem_anomaly.adapters.frames import TabularData
from siem_anomaly.adapters.registry import get_adapter
from siem_anomaly.core.profile import DataProfile
from siem_anomaly.incidents import IncidentEvidenceStore
from siem_anomaly.persistence.layout import EngagementPaths
from siem_anomaly.persistence.policy import PersistencePolicy


@dataclass(frozen=True, slots=True)
class EngagementContext:
    root: Path
    paths: EngagementPaths
    policy: PersistencePolicy
    incidents: IncidentEvidenceStore

    @classmethod
    def open(cls, root: str | Path) -> "EngagementContext":
        root_path = Path(root).expanduser().resolve()
        paths = EngagementPaths(root_path)
        paths.initialize()
        policy = PersistencePolicy()
        return cls(
            root=root_path,
            paths=paths,
            policy=policy,
            incidents=IncidentEvidenceStore(paths.incidents, policy),
        )

    def profile(self, data: TabularData, *, source: str) -> DataProfile:
        return get_adapter(source).profile(data)

    def normalize(self, data: TabularData, *, source: str) -> pl.DataFrame:
        return get_adapter(source).normalize(data)

    def discover(self, data: TabularData, *, source: str) -> frozenset[str]:
        profile = self.profile(data, source=source)
        return frozenset(capability.value for capability in profile.capabilities)
