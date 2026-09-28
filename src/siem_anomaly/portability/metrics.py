"""Evaluate feature portability from approved per-environment summaries only."""

import json
import statistics
from dataclasses import asdict, dataclass
from pathlib import Path

from siem_anomaly.feature_catalog import PortabilityExpectation


@dataclass(frozen=True, slots=True)
class EnvironmentFeatureMetrics:
    environment_id: str
    feature_id: str
    effect_size: float
    incident_recall: float
    precision_at_25: float
    false_positive_rate: float
    rank_contribution: float
    ablation_delta: float
    approved_for_export: bool = False


@dataclass(frozen=True, slots=True)
class PortabilityAssessment:
    feature_id: str
    environments_tested: int
    effect_size_median: float
    incident_recall_median: float
    precision_at_25_median: float
    false_positive_rate_median: float
    positive_rank_fraction: float
    evidence: PortabilityExpectation


@dataclass(frozen=True, slots=True)
class LeaveOneEnvironmentOutResult:
    feature_id: str
    held_out_environment: str
    training_recall_median: float
    held_out_recall: float
    generalizes: bool


def assess_portability(
    summaries: tuple[EnvironmentFeatureMetrics, ...],
    *,
    feature_id: str,
) -> PortabilityAssessment:
    selected = tuple(summary for summary in summaries if summary.feature_id == feature_id)
    if not selected:
        raise ValueError(f"No summaries for feature: {feature_id}")
    effect = statistics.median(summary.effect_size for summary in selected)
    recall = statistics.median(summary.incident_recall for summary in selected)
    precision = statistics.median(summary.precision_at_25 for summary in selected)
    fp_rate = statistics.median(summary.false_positive_rate for summary in selected)
    positive_rank = sum(summary.rank_contribution > 0 for summary in selected) / len(selected)

    if len(selected) >= 3 and recall >= 0.7 and fp_rate <= 0.1 and positive_rank >= 0.67:
        evidence = PortabilityExpectation.HIGH
    elif len(selected) >= 2 and recall >= 0.5 and fp_rate <= 0.25 and positive_rank >= 0.5:
        evidence = PortabilityExpectation.MEDIUM
    else:
        evidence = PortabilityExpectation.LOW

    return PortabilityAssessment(
        feature_id=feature_id,
        environments_tested=len(selected),
        effect_size_median=effect,
        incident_recall_median=recall,
        precision_at_25_median=precision,
        false_positive_rate_median=fp_rate,
        positive_rank_fraction=positive_rank,
        evidence=evidence,
    )


def leave_one_environment_out(
    summaries: tuple[EnvironmentFeatureMetrics, ...],
    *,
    feature_id: str,
    recall_tolerance: float = 0.2,
) -> tuple[LeaveOneEnvironmentOutResult, ...]:
    selected = tuple(summary for summary in summaries if summary.feature_id == feature_id)
    if len(selected) < 3:
        return ()
    results: list[LeaveOneEnvironmentOutResult] = []
    for held_out in selected:
        training = [item for item in selected if item.environment_id != held_out.environment_id]
        training_recall = statistics.median(item.incident_recall for item in training)
        generalizes = held_out.incident_recall >= max(0.0, training_recall - recall_tolerance)
        results.append(
            LeaveOneEnvironmentOutResult(
                feature_id=feature_id,
                held_out_environment=held_out.environment_id,
                training_recall_median=training_recall,
                held_out_recall=held_out.incident_recall,
                generalizes=generalizes,
            )
        )
    return tuple(results)


def export_approved_summaries(
    summaries: tuple[EnvironmentFeatureMetrics, ...],
    destination: Path,
) -> Path:
    """Export only explicitly approved metrics; no event/relationship data is accepted."""
    approved = [asdict(summary) for summary in summaries if summary.approved_for_export]
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(approved, indent=2, sort_keys=True), encoding="utf-8")
    return destination
