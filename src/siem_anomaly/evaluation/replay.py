"""Leakage-safe replay of known incidents against pre-incident behavioral history."""

import json
import math
import tempfile
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path

import polars as pl

from siem_anomaly.adapters.frames import TabularData
from siem_anomaly.adapters.registry import get_adapter
from siem_anomaly.core.domain import Finding
from siem_anomaly.detectors.identity import detect_identity
from siem_anomaly.features.identity import derive_identity_features
from siem_anomaly.features.store import FeatureRepository
from siem_anomaly.persistence.layout import EngagementPaths
from siem_anomaly.persistence.policy import PersistencePolicy
from siem_anomaly.persistence.stores import EngagementStores


@dataclass(frozen=True, slots=True)
class IncidentDefinition:
    incident_id: str
    source: str
    start: datetime
    end: datetime
    entities: tuple[str, ...]
    exclusion_start: datetime | None = None

    def __post_init__(self) -> None:
        if self.end < self.start:
            raise ValueError("Incident end must not be before start")
        if not self.entities:
            raise ValueError("At least one incident entity is required")


@dataclass(frozen=True, slots=True)
class ReplayMetrics:
    incident_rank: int | None
    precision_at_10: float
    precision_at_25: float
    precision_at_50: float
    recall_at_10: float
    recall_at_25: float
    recall_at_50: float
    false_positives: int
    time_to_first_signal_seconds: float | None


@dataclass(frozen=True, slots=True)
class ReplayReport:
    incident: IncidentDefinition
    metrics: ReplayMetrics
    detector_contribution: dict[str, int]
    false_positives_by_detector: dict[str, int]
    false_positives_by_entity: dict[str, int]
    effect_sizes: dict[str, float]
    ablation_rank_without_detector: dict[str, int | None]
    finding_count: int


def _with_timestamp(frame: pl.DataFrame) -> pl.DataFrame:
    return frame.with_columns(
        pl.col("timestamp")
        .cast(pl.Utf8)
        .str.to_datetime(strict=False, time_zone="UTC")
        .alias("_ts")
    ).drop_nulls(["_ts"])


def _is_incident_finding(finding: Finding, incident: IncidentDefinition) -> bool:
    entity_match = finding.entity in incident.entities
    time_match = finding.end >= incident.start and finding.start <= incident.end
    return entity_match and time_match


def _precision_at(findings: list[Finding], incident: IncidentDefinition, k: int) -> float:
    top = findings[:k]
    if not top:
        return 0.0
    return sum(_is_incident_finding(finding, incident) for finding in top) / len(top)


def _recall_at(findings: list[Finding], incident: IncidentDefinition, k: int) -> float:
    return float(any(_is_incident_finding(finding, incident) for finding in findings[:k]))


def _incident_rank(findings: list[Finding], incident: IncidentDefinition) -> int | None:
    for index, finding in enumerate(findings, start=1):
        if _is_incident_finding(finding, incident):
            return index
    return None


def _effect_size(incident_values: list[float], control_values: list[float]) -> float:
    if not incident_values or not control_values:
        return 0.0
    mean_incident = sum(incident_values) / len(incident_values)
    mean_control = sum(control_values) / len(control_values)
    combined = incident_values + control_values
    mean_all = sum(combined) / len(combined)
    variance = sum((value - mean_all) ** 2 for value in combined) / max(1, len(combined) - 1)
    standard_deviation = math.sqrt(variance)
    if standard_deviation == 0:
        return 0.0
    return (mean_incident - mean_control) / standard_deviation


def _feature_effect_sizes(
    replay_frame: pl.DataFrame,
    incident: IncidentDefinition,
) -> dict[str, float]:
    batch = derive_identity_features(replay_frame)
    actor_hour = batch.actor_hour
    if actor_hour.is_empty():
        return {}
    incident_rows = actor_hour.filter(pl.col("actor").is_in(incident.entities))
    control_rows = actor_hour.filter(~pl.col("actor").is_in(incident.entities))
    numeric = [
        column
        for column, dtype in actor_hour.schema.items()
        if dtype.is_numeric() and column not in {"weekday", "hour"}
    ]
    effects: dict[str, float] = {}
    for column in numeric:
        incident_values = [
            float(value) for value in incident_rows.get_column(column).drop_nulls().to_list()
        ]
        control_values = [
            float(value) for value in control_rows.get_column(column).drop_nulls().to_list()
        ]
        effects[column] = _effect_size(incident_values, control_values)
    return effects


def _matched_controls(
    baseline: pl.DataFrame,
    incident: IncidentDefinition,
    *,
    limit: int = 100,
) -> pl.DataFrame:
    with_time = _with_timestamp(baseline)
    incident_hour = incident.start.astimezone(UTC).hour
    incident_weekday = incident.start.astimezone(UTC).isoweekday()
    return (
        with_time.filter(
            (~pl.col("actor").is_in(incident.entities))
            & (pl.col("_ts").dt.hour() == incident_hour)
            & (pl.col("_ts").dt.weekday() == incident_weekday)
        )
        .head(limit)
        .drop("_ts")
    )


def replay_known_incident(
    *,
    evaluation_root: Path,
    baseline_data: TabularData,
    replay_data: TabularData,
    incident: IncidentDefinition,
    feature_version: str = "identity-v1",
) -> ReplayReport:
    """Replay without future-data leakage and persist only derived evaluation output."""
    adapter = get_adapter(incident.source)
    baseline = _with_timestamp(adapter.normalize(baseline_data))
    cutoff = incident.exclusion_start or incident.start
    baseline = baseline.filter(pl.col("_ts") < cutoff.astimezone(UTC)).drop("_ts")
    replay = adapter.normalize(replay_data)

    with tempfile.TemporaryDirectory(prefix="siem-anomaly-replay-") as temp_dir:
        paths = EngagementPaths(Path(temp_dir))
        paths.initialize()
        stores = EngagementStores.create(paths=paths, policy=PersistencePolicy())
        repository = FeatureRepository(stores)
        if not baseline.is_empty():
            repository.persist_batch(
                derive_identity_features(baseline),
                feature_version=feature_version,
                token="pre-incident-baseline",
            )
        findings = detect_identity(
            replay,
            source=incident.source,
            repository=repository,
            feature_version=feature_version,
        )

    ranked = sorted(findings, key=lambda finding: (-finding.score, finding.finding_id))
    positives = [finding for finding in ranked if _is_incident_finding(finding, incident)]
    negatives = [finding for finding in ranked if not _is_incident_finding(finding, incident)]
    first_signal = min((finding.start for finding in positives), default=None)

    detector_contribution = Counter(finding.detector_id for finding in positives)
    fp_detector = Counter(finding.detector_id for finding in negatives)
    fp_entity = Counter(finding.entity or "<none>" for finding in negatives)

    ablation: dict[str, int | None] = {}
    for detector_id in sorted({finding.detector_id for finding in ranked}):
        without = [finding for finding in ranked if finding.detector_id != detector_id]
        ablation[detector_id] = _incident_rank(without, incident)

    controls = _matched_controls(baseline, incident)
    effect_input = (
        pl.concat([replay, controls], how="diagonal_relaxed") if not controls.is_empty() else replay
    )

    report = ReplayReport(
        incident=incident,
        metrics=ReplayMetrics(
            incident_rank=_incident_rank(ranked, incident),
            precision_at_10=_precision_at(ranked, incident, 10),
            precision_at_25=_precision_at(ranked, incident, 25),
            precision_at_50=_precision_at(ranked, incident, 50),
            recall_at_10=_recall_at(ranked, incident, 10),
            recall_at_25=_recall_at(ranked, incident, 25),
            recall_at_50=_recall_at(ranked, incident, 50),
            false_positives=len(negatives),
            time_to_first_signal_seconds=(
                (first_signal - incident.start).total_seconds()
                if first_signal is not None
                else None
            ),
        ),
        detector_contribution=dict(detector_contribution),
        false_positives_by_detector=dict(fp_detector),
        false_positives_by_entity=dict(fp_entity),
        effect_sizes=_feature_effect_sizes(effect_input, incident),
        ablation_rank_without_detector=ablation,
        finding_count=len(ranked),
    )
    _persist_report(evaluation_root, report)
    return report


def _persist_report(root: Path, report: ReplayReport) -> Path:
    destination_dir = root / "replays"
    destination_dir.mkdir(parents=True, exist_ok=True)
    destination = destination_dir / f"{report.incident.incident_id}.json"
    payload = asdict(report)
    incident = payload["incident"]
    if isinstance(incident, dict):
        incident["start"] = report.incident.start.isoformat()
        incident["end"] = report.incident.end.isoformat()
        incident["exclusion_start"] = (
            report.incident.exclusion_start.isoformat()
            if report.incident.exclusion_start is not None
            else None
        )
    destination.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return destination
