"""Initial explainable identity detectors."""

import hashlib
import statistics
from collections import defaultdict
from datetime import UTC, datetime

import polars as pl

from siem_anomaly.core.domain import Finding
from siem_anomaly.features.identity import derive_identity_features
from siem_anomaly.features.store import FeatureRepository


def _finding_id(detector_id: str, entity: str, start: datetime, detail: str) -> str:
    raw = f"{detector_id}|{entity}|{start.isoformat()}|{detail}"
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


def _to_datetime(value: object) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(UTC)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)


def _p95(values: list[int]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int(round(0.95 * (len(ordered) - 1)))))
    return float(ordered[index])


def _append_relationship_findings(
    *,
    current: pl.DataFrame,
    history: pl.DataFrame,
    frame: pl.DataFrame,
    source: str,
    findings: list[Finding],
) -> None:
    if current.is_empty():
        return
    history_pairs: dict[tuple[str, str], int] = {}
    if not history.is_empty():
        rolled = history.group_by(["actor", "source_ip"]).agg(
            pl.col("event_count").sum().alias("event_count")
        )
        history_pairs = {
            (str(row["actor"]), str(row["source_ip"])): int(row["event_count"])
            for row in rolled.iter_rows(named=True)
        }
    historical_actors = {actor for actor, _ in history_pairs}
    event_times = (
        frame.with_columns(
            pl.col("timestamp")
            .cast(pl.Utf8)
            .str.to_datetime(strict=False, time_zone="UTC")
            .alias("_ts")
        )
        .drop_nulls(["_ts"])
        .select(pl.col("_ts").min().alias("start"), pl.col("_ts").max().alias("end"))
        .row(0, named=True)
    )
    start = _to_datetime(event_times["start"])
    end = _to_datetime(event_times["end"])

    for row in current.iter_rows(named=True):
        actor = str(row["actor"])
        source_ip = str(row["source_ip"])
        count = history_pairs.get((actor, source_ip))
        if count is None:
            findings.append(
                Finding(
                    finding_id=_finding_id(
                        "identity.relationship_novelty",
                        actor,
                        start,
                        source_ip,
                    ),
                    detector_id="identity.relationship_novelty",
                    source=source,
                    start=start,
                    end=end,
                    score=1.0,
                    entity=actor,
                    reason_codes=("new_actor_source_ip",),
                    reasons=(f"source IP {source_ip} not seen in historical actor/IP state",),
                )
            )
            if actor in historical_actors:
                findings.append(
                    Finding(
                        finding_id=_finding_id(
                            "identity.relationship_change",
                            actor,
                            start,
                            source_ip,
                        ),
                        detector_id="identity.relationship_change",
                        source=source,
                        start=start,
                        end=end,
                        score=0.8,
                        entity=actor,
                        reason_codes=("established_actor_new_source_ip",),
                        reasons=(
                            f"established actor shifted to previously unseen source IP {source_ip}",
                        ),
                    )
                )
        elif count <= 2:
            findings.append(
                Finding(
                    finding_id=_finding_id(
                        "identity.conditional_rarity",
                        actor,
                        start,
                        source_ip,
                    ),
                    detector_id="identity.conditional_rarity",
                    source=source,
                    start=start,
                    end=end,
                    score=1.0 / (count + 1),
                    entity=actor,
                    reason_codes=("rare_actor_source_ip",),
                    reasons=(f"source IP {source_ip} observed only {count} historical events",),
                )
            )


def detect_identity(
    frame: pl.DataFrame,
    *,
    source: str,
    repository: FeatureRepository,
    feature_version: str,
) -> tuple[Finding, ...]:
    current = derive_identity_features(frame)
    findings: list[Finding] = []

    history_ip = repository.read_state("actor_ip", feature_version=feature_version)
    _append_relationship_findings(
        current=current.actor_ip,
        history=history_ip,
        frame=frame,
        source=source,
        findings=findings,
    )

    historical_actor_hour = repository.read_feature(
        "actor_hour",
        feature_version=feature_version,
    )
    if historical_actor_hour.is_empty() or current.actor_hour.is_empty():
        return tuple(sorted(findings, key=lambda item: item.finding_id))

    historical = historical_actor_hour.with_columns(
        [
            pl.col("window").dt.weekday().alias("weekday"),
            pl.col("window").dt.hour().alias("hour"),
        ]
    )
    actor_values: dict[tuple[str, int, int], list[int]] = defaultdict(list)
    organization_values: dict[tuple[int, int], list[int]] = defaultdict(list)
    for row in historical.iter_rows(named=True):
        actor = str(row["actor"])
        weekday = int(row["weekday"])
        hour = int(row["hour"])
        count = int(row["event_count"])
        actor_values[(actor, weekday, hour)].append(count)
        organization_values[(weekday, hour)].append(count)

    current_enriched = current.actor_hour.with_columns(
        [
            pl.col("window").dt.weekday().alias("weekday"),
            pl.col("window").dt.hour().alias("hour"),
        ]
    )
    for row in current_enriched.iter_rows(named=True):
        actor = str(row["actor"])
        window = _to_datetime(row["window"])
        weekday = int(row["weekday"])
        hour = int(row["hour"])
        count = int(row["event_count"])
        values = actor_values.get((actor, weekday, hour))

        if not values:
            findings.append(
                Finding(
                    finding_id=_finding_id("identity.rhythm_deviation", actor, window, "hour"),
                    detector_id="identity.rhythm_deviation",
                    source=source,
                    start=window,
                    end=window,
                    score=1.0,
                    entity=actor,
                    reason_codes=("unseen_actor_weekday_hour",),
                    reasons=("activity occurred in an unseen weekday/hour baseline bucket",),
                )
            )
        else:
            median = float(statistics.median(values))
            p95 = _p95(values)
            if count > max(p95, median * 2.0, 1.0):
                score = min(1.0, count / max(p95, 1.0) / 4.0)
                findings.append(
                    Finding(
                        finding_id=_finding_id(
                            "identity.volume_deviation",
                            actor,
                            window,
                            str(count),
                        ),
                        detector_id="identity.volume_deviation",
                        source=source,
                        start=window,
                        end=window,
                        score=score,
                        entity=actor,
                        reason_codes=("actor_hour_volume_above_p95",),
                        reasons=(
                            f"hourly event count {count} exceeds historical p95 {p95:.2f}",
                        ),
                    )
                )

            deviations = [abs(value - median) for value in values]
            mad = float(statistics.median(deviations))
            robust_score = (
                abs(count - median) / (1.4826 * mad)
                if mad > 0
                else (4.0 if count > max(median * 2.0, median + 1.0) else 0.0)
            )
            if robust_score >= 3.5:
                findings.append(
                    Finding(
                        finding_id=_finding_id(
                            "identity.robust_historical_deviation",
                            actor,
                            window,
                            str(count),
                        ),
                        detector_id="identity.robust_historical_deviation",
                        source=source,
                        start=window,
                        end=window,
                        score=min(1.0, robust_score / 8.0),
                        entity=actor,
                        reason_codes=("actor_hour_robust_deviation",),
                        reasons=(
                            f"hourly volume robust deviation score is {robust_score:.2f}",
                        ),
                    )
                )

        organization = organization_values.get((weekday, hour), [])
        organization_p95 = _p95(organization)
        if organization and count > max(organization_p95 * 2.0, organization_p95 + 1.0):
            findings.append(
                Finding(
                    finding_id=_finding_id(
                        "identity.organization_relative_deviation",
                        actor,
                        window,
                        str(count),
                    ),
                    detector_id="identity.organization_relative_deviation",
                    source=source,
                    start=window,
                    end=window,
                    score=min(1.0, count / max(organization_p95, 1.0) / 4.0),
                    entity=actor,
                    reason_codes=("actor_volume_above_organization_p95",),
                    reasons=(
                        f"actor hourly count {count} exceeds organization p95 "
                        f"{organization_p95:.2f}",
                    ),
                )
            )

    return tuple(sorted(findings, key=lambda item: item.finding_id))
