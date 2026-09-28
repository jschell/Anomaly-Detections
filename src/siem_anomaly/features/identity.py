"""Identity-oriented aggregate features and behavioral relationship state."""

from dataclasses import dataclass

import polars as pl


@dataclass(frozen=True, slots=True)
class DerivedBatch:
    actor_hour: pl.DataFrame
    actor_day: pl.DataFrame
    actor_ip: pl.DataFrame
    actor_app: pl.DataFrame
    actor_country: pl.DataFrame


def _with_time(frame: pl.DataFrame) -> pl.DataFrame:
    return frame.with_columns(
        pl.col("timestamp")
        .cast(pl.Utf8)
        .str.to_datetime(strict=False, time_zone="UTC")
        .alias("_ts")
    ).drop_nulls(["_ts"])


def _actor_time_features(frame: pl.DataFrame, *, every: str) -> pl.DataFrame:
    with_time = _with_time(frame)
    expressions: list[pl.Expr] = [
        pl.len().alias("event_count"),
    ]
    if "outcome" in with_time.columns:
        success = pl.col("outcome").cast(pl.Utf8) == "0"
        expressions.extend(
            [
                success.sum().alias("success_count"),
                (~success).sum().alias("failure_count"),
            ]
        )
    for column, alias in (
        ("source_ip", "unique_ips"),
        ("application", "unique_apps"),
        ("country", "unique_countries"),
    ):
        if column in with_time.columns:
            expressions.append(pl.col(column).drop_nulls().n_unique().alias(alias))
    return (
        with_time.with_columns(pl.col("_ts").dt.truncate(every).alias("window"))
        .group_by(["actor", "window"])
        .agg(expressions)
        .sort(["actor", "window"])
    )


def _relationship_state(frame: pl.DataFrame, value_column: str) -> pl.DataFrame:
    if value_column not in frame.columns:
        return pl.DataFrame()
    with_time = _with_time(frame).drop_nulls(["actor", value_column])
    if with_time.is_empty():
        return pl.DataFrame()
    return (
        with_time.with_columns(pl.col("_ts").dt.date().alias("_date"))
        .group_by(["actor", value_column])
        .agg(
            [
                pl.col("_date").min().alias("first_seen_date"),
                pl.col("_date").max().alias("last_seen_date"),
                pl.len().alias("event_count"),
                pl.col("_date").n_unique().alias("days_seen"),
            ]
        )
        .with_columns((1.0 / pl.col("event_count")).alias("rarity_score"))
        .sort(["actor", value_column])
    )


def derive_identity_features(frame: pl.DataFrame) -> DerivedBatch:
    """Derive aggregate identity behavior without preserving event-level rows."""
    if "actor" not in frame.columns or "timestamp" not in frame.columns:
        raise ValueError("Canonical actor and timestamp fields are required")
    return DerivedBatch(
        actor_hour=_actor_time_features(frame, every="1h"),
        actor_day=_actor_time_features(frame, every="1d"),
        actor_ip=_relationship_state(frame, "source_ip"),
        actor_app=_relationship_state(frame, "application"),
        actor_country=_relationship_state(frame, "country"),
    )
