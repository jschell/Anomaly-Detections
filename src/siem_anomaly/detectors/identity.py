"""Initial explainable identity detectors."""

import hashlib
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
    if not current.actor_ip.is_empty():
        history_pairs: dict[tuple[str, str], int] = {}
        if not history_ip.is_empty():
            rolled = history_ip.group_by(["actor", "source_ip"]).agg(
                pl.col("event_count").sum().alias("event_count")
            )
            history_pairs = {
                (str(row["actor"]), str(row["source_ip"])): int(row["event_count"])
                for row in rolled.iter_rows(named=True)
            }
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
        for row in current.actor_ip.iter_rows(named=True):
            actor = str(row["actor"])
            source_ip = str(row["source_ip"])
            key = (actor, source_ip)
            count = history_pairs.get(key)
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
    rhythm = historical.group_by(["actor", "weekday", "hour"]).agg(
        [
            pl.col("event_count").median().alias("median_events"),
            pl.col("event_count").quantile(0.95).alias("p95_events"),
        ]
    )
    rhythm_map = {
        (str(row["actor"]), int(row["weekday"]), int(row["hour"])): (
            float(row["median_events"]),
            float(row["p95_events"]),
        )
        for row in rhythm.iter_rows(named=True)
    }

    current_enriched = current.actor_hour.with_columns(
        [
            pl.col("window").dt.weekday().alias("weekday"),
            pl.col("window").dt.hour().alias("hour"),
        ]
    )
    for row in current_enriched.iter_rows(named=True):
        actor = str(row["actor"])
        window = _to_datetime(row["window"])
        key = (actor, int(row["weekday"]), int(row["hour"]))
        baseline = rhythm_map.get(key)
        if baseline is None:
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
            continue
        median, p95 = baseline
        count = int(row["event_count"])
        if count > max(p95, median * 2.0, 1.0):
            score = min(1.0, count / max(p95, 1.0) / 4.0)
            findings.append(
                Finding(
                    finding_id=_finding_id("identity.volume_deviation", actor, window, str(count)),
                    detector_id="identity.volume_deviation",
                    source=source,
                    start=window,
                    end=window,
                    score=score,
                    entity=actor,
                    reason_codes=("actor_hour_volume_above_p95",),
                    reasons=(f"hourly event count {count} exceeds historical p95 {p95:.2f}",),
                )
            )
    return tuple(sorted(findings, key=lambda item: item.finding_id))
