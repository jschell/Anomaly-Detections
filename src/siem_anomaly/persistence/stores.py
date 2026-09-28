"""Purpose-specific derived Parquet stores."""

from dataclasses import dataclass
from pathlib import Path

from siem_anomaly.adapters.frames import TabularData, to_polars
from siem_anomaly.persistence.layout import EngagementPaths
from siem_anomaly.persistence.policy import ArtifactKind, PersistencePolicy


def _safe_destination(root: Path, relative_path: str | Path) -> Path:
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Artifact path must remain inside its engagement store")
    resolved_root = root.resolve()
    destination = (resolved_root / relative).resolve()
    if resolved_root not in destination.parents and destination != resolved_root:
        raise ValueError("Artifact path must remain inside its engagement store")
    return destination


@dataclass(frozen=True, slots=True)
class DerivedParquetStore:
    root: Path
    kind: ArtifactKind
    policy: PersistencePolicy

    def write(self, relative_path: str | Path, data: TabularData) -> Path:
        self.policy.assert_allowed(self.kind)
        destination = _safe_destination(self.root, relative_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        to_polars(data).write_parquet(destination)
        return destination


@dataclass(frozen=True, slots=True)
class EngagementStores:
    features: DerivedParquetStore
    state: DerivedParquetStore
    baselines: DerivedParquetStore
    evaluation: DerivedParquetStore

    @classmethod
    def create(cls, *, paths: EngagementPaths, policy: PersistencePolicy) -> "EngagementStores":
        return cls(
            features=DerivedParquetStore(paths.features, ArtifactKind.AGGREGATE_FEATURE, policy),
            state=DerivedParquetStore(paths.state, ArtifactKind.RELATIONSHIP_STATE, policy),
            baselines=DerivedParquetStore(paths.baselines, ArtifactKind.BASELINE, policy),
            evaluation=DerivedParquetStore(
                paths.evaluation, ArtifactKind.EVALUATION_RESULT, policy
            ),
        )
