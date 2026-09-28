"""Persistence and baseline rebuilding for derived behavioral features."""

from dataclasses import dataclass
from pathlib import Path

import polars as pl

from siem_anomaly.features.identity import DerivedBatch
from siem_anomaly.persistence.stores import EngagementStores


def _read_all(root: Path) -> pl.DataFrame:
    files = sorted(root.rglob("*.parquet"))
    if not files:
        return pl.DataFrame()
    return pl.concat([pl.read_parquet(path) for path in files], how="diagonal_relaxed")


@dataclass(frozen=True, slots=True)
class FeatureRepository:
    stores: EngagementStores

    def persist_batch(
        self,
        batch: DerivedBatch,
        *,
        feature_version: str,
        token: str,
    ) -> int:
        count = 0
        for name, frame in (
            ("actor_hour", batch.actor_hour),
            ("actor_day", batch.actor_day),
            ("service_hour", batch.service_hour),
            ("resource_hour", batch.resource_hour),
            ("operation_hour", batch.operation_hour),
            ("environment_hour", batch.environment_hour),
        ):
            if not frame.is_empty():
                self.stores.features.write(
                    Path(name) / feature_version / f"{token}.parquet",
                    frame,
                )
                count += frame.height
        for name, frame in (
            ("actor_ip", batch.actor_ip),
            ("actor_app", batch.actor_app),
            ("actor_country", batch.actor_country),
            ("actor_resource", batch.actor_resource),
            ("actor_operation", batch.actor_operation),
        ):
            if not frame.is_empty():
                self.stores.state.write(
                    Path(name) / feature_version / f"{token}.parquet",
                    frame,
                )
                count += frame.height
        return count

    def read_feature(self, name: str, *, feature_version: str) -> pl.DataFrame:
        return _read_all(self.stores.features.root / name / feature_version)

    def read_state(self, name: str, *, feature_version: str) -> pl.DataFrame:
        return _read_all(self.stores.state.root / name / feature_version)

    def rebuild_rhythm(self, *, feature_version: str) -> tuple[pl.DataFrame, pl.DataFrame]:
        actor_hour = self.read_feature("actor_hour", feature_version=feature_version)
        environment_hour = self.read_feature("environment_hour", feature_version=feature_version)
        if actor_hour.is_empty():
            return pl.DataFrame(), pl.DataFrame()

        enriched = actor_hour.with_columns(
            [
                pl.col("window").dt.weekday().alias("weekday"),
                pl.col("window").dt.hour().alias("hour"),
            ]
        )
        actor_rhythm = (
            enriched.group_by(["actor", "weekday", "hour"])
            .agg(
                [
                    pl.col("event_count").median().alias("median_events"),
                    pl.col("event_count").quantile(0.95).alias("p95_events"),
                    pl.len().alias("observations"),
                ]
            )
            .sort(["actor", "weekday", "hour"])
        )

        environment_rhythm = pl.DataFrame()
        if not environment_hour.is_empty():
            environment_rhythm = (
                environment_hour.with_columns(
                    [
                        pl.col("window").dt.weekday().alias("weekday"),
                        pl.col("window").dt.hour().alias("hour"),
                    ]
                )
                .group_by(["weekday", "hour"])
                .agg(
                    [
                        pl.col("event_count").median().alias("median_events"),
                        pl.col("event_count").quantile(0.95).alias("p95_events"),
                        pl.len().alias("observations"),
                    ]
                )
                .sort(["weekday", "hour"])
            )

        self.stores.baselines.write(
            Path("actor_rhythm") / feature_version / "current.parquet",
            actor_rhythm,
        )
        if not environment_rhythm.is_empty():
            self.stores.baselines.write(
                Path("environment_rhythm") / feature_version / "current.parquet",
                environment_rhythm,
            )
        return actor_rhythm, environment_rhythm
