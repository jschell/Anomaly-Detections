"""Purpose-specific derived Parquet stores."""

from dataclasses import dataclass
from pathlib import Path

from siem_anomaly.adapters.frames import TabularData, to_polars
from siem_anomaly.persistence.policy import ArtifactKind, PersistencePolicy


def _safe_destination(root: Path, relative_path: str | Path) -> Path:
    relative = Path(relative_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("Artifact path must remain inside its engagement store")
    destination = (root / relative).resolve()
    if root.resolve() not in destination.parents and destination != root.resolve():
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
    def create(cls, *, root_paths: object, policy: PersistencePolicy) -> "EngagementStores":
        from siem_anomaly.persistence.layout import EngagementPaths

        if not isinstance(root_paths, EngagementPaths):
            raise TypeError("root_paths must be EngagementPaths")
        return cls(
            features=DerivedParquetStore(
                root_paths.features, ArtifactKind.AGGREGATE_FEATURE, policy
            ),
            state=DerivedParquetStore(
                root_paths.state, ArtifactKind.RELATIONSHIP_STATE, policy
            ),
            baselines=DerivedParquetStore(root_paths.baselines, ArtifactKind.BASELINE, policy),
            evaluation=DerivedParquetStore(
                root_paths.evaluation, ArtifactKind.EVALUATION_RESULT, policy
            ),
        )
