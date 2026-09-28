"""Identity-oriented aggregate features and behavioral relationship state."""

from dataclasses import dataclass

import polars as pl


@dataclass(frozen=True, slots=True)
class DerivedBatch:
    actor_hour: pl.DataFrame
    actor_day: pl.DataFrame
    service_hour: pl.DataFrame
    resource_hour: pl.DataFrame
    operation_hour: pl.DataFrame
    environment_hour: pl.DataFrame
    actor_ip: pl.DataFrame
    actor_app: pl.DataFrame
    actor_country: pl.DataFrame
    actor_resource: pl.DataFrame
    actor_operation: pl.DataFrame


def _with_time(frame: pl.DataFrame) -> pl.DataFrame:
    return frame.with_columns(
        pl.col("timestamp")
        .cast(pl.Utf8)
        .str.to_datetime(strict=False, time_zone="UTC")
        .alias("_ts")
    ).drop_nulls(["_ts"])


def _actor_time_features(frame: pl.DataFrame, *, every: str) -> pl.DataFrame:
    with_time = _with_time(frame)
    expressions: list[pl.Expr] = [pl.len().alias("event_count")]
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
        ("target", "unique_resources"),
        ("action", "unique_operations"),
    ):
        if column in with_time.columns:
            expressions.append(pl.col(column).drop_nulls().n_unique().alias(alias))
    return (
        with_time.with_columns(pl.col("_ts").dt.truncate(every).alias("window"))
        .group_by(["actor", "window"])
        .agg(expressions)
        .sort(["actor", "window"])
    )


def _dimension_hour(frame: pl.DataFrame, column: str, output_name: str) -> pl.DataFrame:
    if column not in frame.columns:
        return pl.DataFrame()
    with_time = _with_time(frame).drop_nulls([column])
    if with_time.is_empty():
        return pl.DataFrame()
    return (
        with_time.with_columns(pl.col("_ts").dt.truncate("1h").alias("window"))
        .group_by([pl.col(column).alias(output_name), "window"])
        .agg(pl.len().alias("event_count"))
        .sort([output_name, "window"])
    )


def _environment_hour(frame: pl.DataFrame) -> pl.DataFrame:
    with_time = _with_time(frame)
    if with_time.is_empty():
        return pl.DataFrame()
    return (
        with_time.with_columns(pl.col("_ts").dt.truncate("1h").alias("window"))
        .group_by("window")
        .agg(
            [
                pl.len().alias("event_count"),
                pl.col("actor").drop_nulls().n_unique().alias("unique_actors"),
            ]
        )
        .sort("window")
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
        service_hour=_dimension_hour(frame, "application", "service"),
        resource_hour=_dimension_hour(frame, "target", "resource"),
        operation_hour=_dimension_hour(frame, "action", "operation"),
        environment_hour=_environment_hour(frame),
        actor_ip=_relationship_state(frame, "source_ip"),
        actor_app=_relationship_state(frame, "application"),
        actor_country=_relationship_state(frame, "country"),
        actor_resource=_relationship_state(frame, "target"),
        actor_operation=_relationship_state(frame, "action"),
    )
