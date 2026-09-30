"""Coverage-gated network-enrichment behavior detectors."""

import hashlib
from datetime import UTC, date, datetime

import polars as pl

from siem_anomaly.core.domain import Finding
from siem_anomaly.features.identity import derive_identity_features
from siem_anomaly.features.store import FeatureRepository

MIN_BASELINE_DAYS = 7
MIN_OBSERVED_DAYS = 2


def _utc(value: object) -> datetime:
    if isinstance(value, datetime):
        return value.astimezone(UTC)
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).astimezone(UTC)


def _finding(
    detector: str,
    actor: str,
    value: str,
    start: datetime,
    end: datetime,
    score: float,
    source: str,
    reason: str,
) -> Finding:
    identifier = hashlib.sha256(
        f"{detector}|{actor}|{start.isoformat()}|{value}".encode()
    ).hexdigest()[:20]
    return Finding(
        finding_id=identifier,
        detector_id=detector,
        source=source,
        start=start,
        end=end,
        score=score,
        entity=actor,
        reason_codes=(detector.rsplit(".", 1)[-1],),
        reasons=(reason,),
    )


def _eligible(history: pl.DataFrame, before: date) -> pl.DataFrame:
    if history.is_empty():
        return history
    return history.filter(pl.col("last_seen_date") < before)


def _sufficient(rows: list[dict[str, object]], before: date) -> bool:
    if not rows:
        return False
    dates = [value for row in rows if isinstance(value := row["first_seen_date"], date)]
    if not dates:
        return False
    first = min(dates)
    days = sum(int(str(row["days_seen"])) for row in rows)
    return (before - first).days >= MIN_BASELINE_DAYS and days >= MIN_OBSERVED_DAYS


def detect_network(
    frame: pl.DataFrame,
    *,
    source: str,
    repository: FeatureRepository,
    feature_version: str,
    enabled: frozenset[str],
    enrichment_source: str,
) -> tuple[Finding, ...]:
    current = derive_identity_features(frame)
    times = frame.select(
        pl.col("timestamp").cast(pl.Utf8).str.to_datetime(strict=False, time_zone="UTC").min(),
        pl.col("timestamp")
        .cast(pl.Utf8)
        .str.to_datetime(strict=False, time_zone="UTC")
        .max()
        .alias("end"),
    ).row(0, named=True)
    if times["timestamp"] is None:
        return ()
    start, end = _utc(times["timestamp"]), _utc(times["end"])
    findings: list[Finding] = []

    if not current.actor_asn.is_empty():
        historical = _eligible(
            repository.read_state("actor_asn", feature_version=feature_version), start.date()
        )
        if not historical.is_empty():
            by_actor: dict[str, list[dict[str, object]]] = {}
            for row in historical.iter_rows(named=True):
                by_actor.setdefault(str(row["actor"]), []).append(row)
            for row in current.actor_asn.iter_rows(named=True):
                actor, asn = str(row["actor"]), str(row["asn"])
                prior = by_actor.get(actor, [])
                if not _sufficient(prior, start.date()):
                    continue
                seen = {str(item["asn"]) for item in prior}
                if asn in seen:
                    continue
                detector = "identity.asn_change" if len(seen) == 1 else "identity.asn_novelty"
                if detector in enabled:
                    findings.append(
                        _finding(
                            detector,
                            actor,
                            asn,
                            start,
                            end,
                            0.75 if len(seen) == 1 else 0.6,
                            source,
                            f"ASN {asn} is new for this actor; "
                            f"{len(seen)} historical ASN(s) were observed",
                        )
                    )

    if not current.actor_network_trait.is_empty() and "identity.network_trait_novelty" in enabled:
        historical = _eligible(
            repository.read_state("actor_network_trait", feature_version=feature_version),
            start.date(),
        )
        if not historical.is_empty():
            by_actor_trait: dict[str, list[dict[str, object]]] = {}
            for row in historical.iter_rows(named=True):
                by_actor_trait.setdefault(str(row["actor"]), []).append(row)
            for row in current.actor_network_trait.iter_rows(named=True):
                actor, trait = str(row["actor"]), str(row["network_trait"])
                prior = by_actor_trait.get(actor, [])
                if _sufficient(prior, start.date()) and trait not in {
                    str(item["network_trait"]) for item in prior
                }:
                    findings.append(
                        _finding(
                            "identity.network_trait_novelty",
                            actor,
                            trait,
                            start,
                            end,
                            0.55,
                            source,
                            f"Network classification {trait} from {enrichment_source} "
                            "is new for this actor",
                        )
                    )

    if "identity.asn_diversity" in enabled and "unique_asns" in current.actor_hour.columns:
        history = repository.read_feature("actor_hour", feature_version=feature_version)
        if not history.is_empty() and "unique_asns" in history.columns:
            for row in current.actor_hour.iter_rows(named=True):
                actor, window = str(row["actor"]), _utc(row["window"])
                count = int(row["unique_asns"] or 0)
                if count < 2:
                    continue
                prior = history.filter(
                    (pl.col("actor") == actor)
                    & (pl.col("window") < window)
                    & pl.col("unique_asns").is_not_null()
                )
                if (
                    prior.height < 3
                    or (window - _utc(prior["window"].min())).days < MIN_BASELINE_DAYS
                ):
                    continue
                p95 = float(prior["unique_asns"].quantile(0.95) or 0)
                if count > max(p95 + 1, p95 * 2):
                    findings.append(
                        _finding(
                            "identity.asn_diversity",
                            actor,
                            str(count),
                            window,
                            window,
                            min(1.0, count / max(p95, 1) / 4),
                            source,
                            f"Actor used {count} distinct ASNs in one hour; "
                            f"historical p95 is {p95:.1f}",
                        )
                    )
    return tuple(sorted(findings, key=lambda item: item.finding_id))
