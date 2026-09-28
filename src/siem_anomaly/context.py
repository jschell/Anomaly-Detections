"""Engagement-scoped entry point for analysis state."""

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import polars as pl

from siem_anomaly.adapters.frames import TabularData
from siem_anomaly.adapters.registry import get_adapter
from siem_anomaly.core.domain import Finding
from siem_anomaly.core.profile import DataProfile
from siem_anomaly.detectors.identity import detect_identity
from siem_anomaly.detectors.registry import DetectorRegistry, build_default_registry
from siem_anomaly.evaluation import IncidentDefinition, ReplayReport, replay_known_incident
from siem_anomaly.features.identity import derive_identity_features
from siem_anomaly.features.store import FeatureRepository
from siem_anomaly.findings import FindingStore
from siem_anomaly.incidents import IncidentEvidenceStore
from siem_anomaly.models import (
    IsolationForestArtifact,
    fit_isolation_forest,
    score_isolation_forest,
)
from siem_anomaly.persistence.layout import EngagementPaths
from siem_anomaly.persistence.policy import PersistencePolicy
from siem_anomaly.persistence.stores import EngagementStores
from siem_anomaly.provenance import CoverageWindow, ManifestRecord, ManifestStore
from siem_anomaly.workflow import AnalystWorkflow


@dataclass(frozen=True, slots=True)
class EngagementContext:
    root: Path
    paths: EngagementPaths
    policy: PersistencePolicy
    stores: EngagementStores
    features: FeatureRepository
    manifests: ManifestStore
    detector_registry: DetectorRegistry
    findings: FindingStore
    incidents: IncidentEvidenceStore
    workflow: AnalystWorkflow

    @classmethod
    def open(cls, root: str | Path) -> "EngagementContext":
        root_path = Path(root).expanduser().resolve()
        paths = EngagementPaths(root_path)
        paths.initialize()
        policy = PersistencePolicy()
        stores = EngagementStores.create(paths=paths, policy=policy)
        return cls(
            root=root_path,
            paths=paths,
            policy=policy,
            stores=stores,
            features=FeatureRepository(stores),
            manifests=ManifestStore(paths.manifests),
            detector_registry=build_default_registry(),
            findings=FindingStore(paths.findings, policy),
            incidents=IncidentEvidenceStore(paths.incidents, policy),
            workflow=AnalystWorkflow(paths.investigations, paths.incidents, policy),
        )

    def profile(self, data: TabularData, *, source: str) -> DataProfile:
        return get_adapter(source).profile(data)

    def normalize(self, data: TabularData, *, source: str) -> pl.DataFrame:
        return get_adapter(source).normalize(data)

    def discover(self, data: TabularData, *, source: str) -> tuple[str, ...]:
        profile = self.profile(data, source=source)
        return tuple(spec.detector_id for spec in self.detector_registry.discover(profile))

    def derive(
        self,
        data: TabularData,
        *,
        source: str,
        query_id: str,
        feature_version: str = "identity-v1",
        window_start: datetime | None = None,
        window_end: datetime | None = None,
    ) -> ManifestRecord:
        frame = self.normalize(data, source=source)
        if frame.is_empty():
            if window_start is None or window_end is None:
                raise ValueError(
                    "Empty SIEM results require explicit window_start and window_end "
                    "so coverage can still be recorded"
                )
            start = window_start.astimezone(UTC)
            end = window_end.astimezone(UTC)
            derived_rows = 0
        else:
            batch = derive_identity_features(frame)
            inferred_start, inferred_end = _event_window(frame)
            start = (window_start or inferred_start).astimezone(UTC)
            end = (window_end or inferred_end).astimezone(UTC)
            provisional = ManifestRecord.create(
                feature_set="identity",
                feature_version=feature_version,
                source=source,
                query_id=query_id,
                start=start,
                end=end,
                source_rows=frame.height,
                derived_rows=0,
                adapter_version="1",
                framework_version="0.0.0",
            )
            derived_rows = self.features.persist_batch(
                batch,
                feature_version=feature_version,
                token=provisional.query_hash,
            )
        if end < start:
            raise ValueError("window_end must not be before window_start")
        record = ManifestRecord.create(
            feature_set="identity",
            feature_version=feature_version,
            source=source,
            query_id=query_id,
            start=start,
            end=end,
            source_rows=frame.height,
            derived_rows=derived_rows,
            adapter_version="1",
            framework_version="0.0.0",
        )
        self.manifests.write(record)
        return record

    def coverage(self, *, feature_version: str = "identity-v1") -> tuple[CoverageWindow, ...]:
        return self.manifests.coverage(
            feature_set="identity",
            feature_version=feature_version,
        )

    def missing_windows(
        self,
        *,
        start: datetime,
        end: datetime,
        feature_version: str = "identity-v1",
    ) -> tuple[CoverageWindow, ...]:
        return self.manifests.missing_windows(
            feature_set="identity",
            feature_version=feature_version,
            start=start,
            end=end,
        )

    def rebuild_baselines(
        self,
        *,
        feature_version: str = "identity-v1",
    ) -> tuple[pl.DataFrame, pl.DataFrame]:
        return self.features.rebuild_rhythm(feature_version=feature_version)

    def detect(
        self,
        data: TabularData,
        *,
        source: str,
        feature_version: str = "identity-v1",
        persist: bool = True,
    ) -> tuple[Finding, ...]:
        frame = self.normalize(data, source=source)
        findings = detect_identity(
            frame,
            source=source,
            repository=self.features,
            feature_version=feature_version,
        )
        if persist and findings:
            self.findings.write(findings, source=source, token=findings[0].finding_id)
        return findings

    def replay(
        self,
        *,
        baseline_data: TabularData,
        replay_data: TabularData,
        incident: IncidentDefinition,
        feature_version: str = "identity-v1",
    ) -> ReplayReport:
        return replay_known_incident(
            evaluation_root=self.paths.evaluation,
            baseline_data=baseline_data,
            replay_data=replay_data,
            incident=incident,
            feature_version=feature_version,
        )

    def train_isolation_forest(
        self,
        *,
        model_id: str,
        feature_version: str = "identity-v1",
        contamination: float = 0.02,
    ) -> IsolationForestArtifact:
        actor_hour = self.features.read_feature("actor_hour", feature_version=feature_version)
        return fit_isolation_forest(
            actor_hour,
            models_root=self.paths.models,
            model_id=model_id,
            feature_version=feature_version,
            contamination=contamination,
        )

    def score_isolation_forest(
        self,
        data: TabularData,
        *,
        source: str,
        artifact: IsolationForestArtifact,
    ) -> pl.DataFrame:
        normalized = self.normalize(data, source=source)
        actor_hour = derive_identity_features(normalized).actor_hour
        return score_isolation_forest(actor_hour, artifact)


def _event_window(frame: pl.DataFrame) -> tuple[datetime, datetime]:
    timestamp = frame.select(
        pl.col("timestamp")
        .cast(pl.Utf8)
        .str.to_datetime(strict=False, time_zone="UTC")
        .min()
        .alias("start"),
        pl.col("timestamp")
        .cast(pl.Utf8)
        .str.to_datetime(strict=False, time_zone="UTC")
        .max()
        .alias("end"),
    ).row(0, named=True)
    return _as_utc(timestamp["start"]), _as_utc(timestamp["end"])


def _as_utc(value: object) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(UTC)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)
