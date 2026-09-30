"""Engagement-scoped entry point for analysis state."""

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import polars as pl

from siem_anomaly.adapters.base import MappingAdapter, SourceAdapter
from siem_anomaly.adapters.frames import TabularData
from siem_anomaly.adapters.registry import get_adapter
from siem_anomaly.core.domain import Finding
from siem_anomaly.core.profile import DataProfile
from siem_anomaly.correlation import (
    CorrelatedFindingGroup,
    EntityResolver,
    FindingObservation,
    correlate_findings,
)
from siem_anomaly.detectors.identity import detect_identity
from siem_anomaly.detectors.network import detect_network
from siem_anomaly.detectors.provider_actions import detect_provider_actions
from siem_anomaly.detectors.registry import DetectorRegistry, build_default_registry
from siem_anomaly.evaluation import IncidentDefinition, ReplayReport, replay_known_incident
from siem_anomaly.feature_catalog import FeatureRegistry, build_core_feature_registry
from siem_anomaly.features.identity import derive_identity_features
from siem_anomaly.features.store import FeatureRepository
from siem_anomaly.findings import FindingStore
from siem_anomaly.incidents import IncidentEvidenceStore
from siem_anomaly.models import (
    IsolationForestArtifact,
    ModelComparison,
    finalize_isolation_forest,
    fit_isolation_forest,
    score_isolation_forest,
)
from siem_anomaly.persistence.config import EngagementConfig, load_or_create_config
from siem_anomaly.persistence.layout import EngagementPaths
from siem_anomaly.persistence.policy import PersistencePolicy
from siem_anomaly.persistence.stores import EngagementStores
from siem_anomaly.provenance import CoverageWindow, ManifestRecord, ManifestStore
from siem_anomaly.workflow import AnalystWorkflow


@dataclass(frozen=True, slots=True)
class EngagementContext:
    root: Path
    paths: EngagementPaths
    config: EngagementConfig
    policy: PersistencePolicy
    stores: EngagementStores
    features: FeatureRepository
    manifests: ManifestStore
    detector_registry: DetectorRegistry
    findings: FindingStore
    incidents: IncidentEvidenceStore
    workflow: AnalystWorkflow
    feature_registry: FeatureRegistry

    @classmethod
    def open(cls, root: str | Path) -> "EngagementContext":
        root_path = Path(root).expanduser().resolve()
        paths = EngagementPaths(root_path)
        paths.initialize()
        config = load_or_create_config(paths.config)
        policy = PersistencePolicy.from_config(config)
        stores = EngagementStores.create(paths=paths, policy=policy)
        return cls(
            root=root_path,
            paths=paths,
            config=config,
            policy=policy,
            stores=stores,
            features=FeatureRepository(stores),
            manifests=ManifestStore(paths.manifests),
            detector_registry=build_default_registry(),
            findings=FindingStore(paths.findings, policy),
            incidents=IncidentEvidenceStore(paths.incidents, policy),
            workflow=AnalystWorkflow(paths.investigations, paths.incidents, policy),
            feature_registry=build_core_feature_registry(),
        )

    def _adapter(self, source: str, enrichment_fields: Mapping[str, str] | None) -> SourceAdapter:
        adapter = get_adapter(source)
        if enrichment_fields:
            if not isinstance(adapter, MappingAdapter):
                raise TypeError("This adapter does not support declarative enrichment bindings")
            return adapter.with_enrichment(enrichment_fields)
        return adapter

    def profile(
        self,
        data: TabularData,
        *,
        source: str,
        enrichment_fields: Mapping[str, str] | None = None,
    ) -> DataProfile:
        return self._adapter(source, enrichment_fields).profile(data)

    def normalize(
        self,
        data: TabularData,
        *,
        source: str,
        enrichment_fields: Mapping[str, str] | None = None,
    ) -> pl.DataFrame:
        return self._adapter(source, enrichment_fields).normalize(data)

    def discover(
        self,
        data: TabularData,
        *,
        source: str,
        enrichment_fields: Mapping[str, str] | None = None,
        feature_version: str | None = None,
        enrichment_source: str | None = None,
        enrichment_version: str | None = None,
    ) -> tuple[str, ...]:
        profile = self.profile(data, source=source, enrichment_fields=enrichment_fields)
        enabled = {spec.detector_id for spec in self.detector_registry.discover(profile)}
        network = {
            "identity.asn_novelty",
            "identity.asn_change",
            "identity.asn_diversity",
            "identity.network_trait_novelty",
        }
        if enabled & network:
            if enrichment_fields and (not enrichment_source or not enrichment_version):
                raise ValueError("Attached enrichment requires source and version provenance")
            version = self._version(profile, feature_version)
            if version == "identity-v1":
                raise ValueError("Network enrichment requires a new feature version")
            identity = self._enrichment_identity(
                source=source,
                feature_version=version,
                enrichment_source=enrichment_source,
                enrichment_version=enrichment_version,
            )
            frame = self.normalize(data, source=source, enrichment_fields=enrichment_fields)
            earliest = frame.select(
                pl.col("timestamp")
                .cast(pl.Utf8)
                .str.to_datetime(strict=False, time_zone="UTC")
                .min()
            ).item()
            if earliest is not None:
                before = _as_utc(earliest)
                if not self._network_covered(
                    source=source,
                    feature_version=version,
                    capability="asn",
                    before=before,
                    enrichment_source=identity[0],
                    enrichment_version=identity[1],
                ):
                    enabled -= {
                        "identity.asn_novelty",
                        "identity.asn_change",
                        "identity.asn_diversity",
                    }
                if not self._network_covered(
                    source=source,
                    feature_version=version,
                    capability="network_trait",
                    before=before,
                    enrichment_source=identity[0],
                    enrichment_version=identity[1],
                ):
                    enabled.discard("identity.network_trait_novelty")
            else:
                enabled -= network
        return tuple(
            spec.detector_id for spec in self.detector_registry.specs if spec.detector_id in enabled
        )

    @staticmethod
    def _version(profile: DataProfile, feature_version: str | None) -> str:
        if feature_version is not None:
            return feature_version
        if {item.canonical_name for item in profile.capability_coverage} & {"asn", "network_trait"}:
            return "identity-network-v1"
        return "identity-v1"

    def _enrichment_identity(
        self,
        *,
        source: str,
        feature_version: str,
        enrichment_source: str | None,
        enrichment_version: str | None,
    ) -> tuple[str, str]:
        identity = (enrichment_source or "source_native", enrichment_version or "1")
        for record in self.manifests.records(
            feature_set="identity", feature_version=feature_version
        ):
            if record.source != source:
                raise ValueError("Network feature versions must be source-scoped")
            if (
                record.source == source
                and record.enrichment_source is not None
                and (record.enrichment_source, record.enrichment_version) != identity
            ):
                raise ValueError(
                    "Enrichment provenance changed; use a new feature version and backfill"
                )
        return identity

    def _network_covered(
        self,
        *,
        source: str,
        feature_version: str,
        capability: str,
        before: datetime,
        enrichment_source: str,
        enrichment_version: str,
    ) -> bool:
        """Require a continuous queried week with this enrichment available."""
        cursor = before - timedelta(days=7)
        records = sorted(
            (
                record
                for record in self.manifests.records(
                    feature_set="identity", feature_version=feature_version
                )
                if record.source == source
                and record.enrichment_source == enrichment_source
                and record.enrichment_version == enrichment_version
                and capability in record.capability_coverage
                and (record.source_rows == 0 or record.capability_coverage[capability] >= 0.95)
            ),
            key=lambda record: record.start,
        )
        for record in records:
            if record.start <= cursor < record.end:
                cursor = record.end
            if cursor >= before:
                return True
        return False

    def derive(
        self,
        data: TabularData,
        *,
        source: str,
        query_id: str,
        feature_version: str | None = None,
        window_start: datetime | None = None,
        window_end: datetime | None = None,
        enrichment_fields: Mapping[str, str] | None = None,
        enrichment_source: str | None = None,
        enrichment_version: str | None = None,
    ) -> ManifestRecord:
        profile = self.profile(data, source=source, enrichment_fields=enrichment_fields)
        feature_version = self._version(profile, feature_version)
        if enrichment_fields and (not enrichment_source or not enrichment_version):
            raise ValueError("Attached enrichment requires source and version provenance")
        has_network = feature_version != "identity-v1" and bool(
            {item.canonical_name for item in profile.capability_coverage} & {"asn", "network_trait"}
        )
        if (
            not has_network
            and feature_version == "identity-v1"
            and (
                {item.canonical_name for item in profile.capability_coverage}
                & {"asn", "network_trait"}
            )
        ):
            raise ValueError("Network enrichment requires a new feature version")
        identity = (
            self._enrichment_identity(
                source=source,
                feature_version=feature_version,
                enrichment_source=enrichment_source,
                enrichment_version=enrichment_version,
            )
            if has_network
            else (None, None)
        )
        coverage = {item.canonical_name: item.completeness for item in profile.capability_coverage}
        frame = self.normalize(data, source=source, enrichment_fields=enrichment_fields)
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
            if end < start:
                raise ValueError("window_end must not be before window_start")
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
                enrichment_source=identity[0],
                enrichment_version=identity[1],
                capability_coverage=coverage,
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
            enrichment_source=identity[0],
            enrichment_version=identity[1],
            capability_coverage=coverage,
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
        feature_version: str | None = None,
        persist: bool = True,
        enrichment_fields: Mapping[str, str] | None = None,
        enrichment_source: str | None = None,
        enrichment_version: str | None = None,
    ) -> tuple[Finding, ...]:
        profile = self.profile(data, source=source, enrichment_fields=enrichment_fields)
        feature_version = self._version(profile, feature_version)
        if enrichment_fields and (not enrichment_source or not enrichment_version):
            raise ValueError("Attached enrichment requires source and version provenance")
        enabled = frozenset(
            self.discover(
                data,
                source=source,
                enrichment_fields=enrichment_fields,
                feature_version=feature_version,
                enrichment_source=enrichment_source,
                enrichment_version=enrichment_version,
            )
        )
        frame = self.normalize(data, source=source, enrichment_fields=enrichment_fields)
        network_findings: tuple[Finding, ...] = ()
        if enabled & {
            "identity.asn_novelty",
            "identity.asn_change",
            "identity.asn_diversity",
            "identity.network_trait_novelty",
        }:
            identity = self._enrichment_identity(
                source=source,
                feature_version=feature_version,
                enrichment_source=enrichment_source,
                enrichment_version=enrichment_version,
            )
            network_findings = detect_network(
                frame,
                source=source,
                repository=self.features,
                feature_version=feature_version,
                enabled=enabled,
                enrichment_source=identity[0],
            )
        findings = (
            *detect_identity(
                frame,
                source=source,
                repository=self.features,
                feature_version=feature_version,
            ),
            *detect_provider_actions(frame, source=source),
            *network_findings,
        )
        if persist and findings:
            self.findings.write(findings, source=source, token=findings[0].finding_id)
        return findings

    def correlate(
        self,
        observations: tuple[FindingObservation, ...],
        *,
        resolver: EntityResolver,
    ) -> tuple[CorrelatedFindingGroup, ...]:
        return correlate_findings(observations, resolver=resolver)

    def replay(
        self,
        *,
        baseline_data: TabularData,
        replay_data: TabularData,
        incident: IncidentDefinition,
        feature_version: str = "identity-v1",
        enrichment_fields: Mapping[str, str] | None = None,
        enrichment_source: str | None = None,
        enrichment_version: str | None = None,
    ) -> ReplayReport:
        return replay_known_incident(
            evaluation_root=self.paths.evaluation,
            baseline_data=baseline_data,
            replay_data=replay_data,
            incident=incident,
            feature_version=feature_version,
            enrichment_fields=enrichment_fields,
            enrichment_source=enrichment_source,
            enrichment_version=enrichment_version,
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

    def finalize_isolation_forest(
        self,
        artifact: IsolationForestArtifact,
        comparison: ModelComparison,
    ) -> IsolationForestArtifact | None:
        return finalize_isolation_forest(
            artifact,
            comparison,
            models_root=self.paths.models,
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
