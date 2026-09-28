from pathlib import Path

import polars as pl
import pytest

from siem_anomaly import open_engagement


def test_derived_feature_store_writes_parquet(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    destination = ctx.stores.features.write(
        "actor_hour/2026-09.parquet",
        pl.DataFrame({"actor": ["a"], "event_count": [5]}),
    )
    assert destination.exists()
    assert destination.is_relative_to(ctx.paths.features)


def test_derived_store_rejects_path_traversal(tmp_path: Path) -> None:
    ctx = open_engagement(tmp_path / "anomaly")
    with pytest.raises(ValueError):
        ctx.stores.features.write("../outside.parquet", pl.DataFrame({"x": [1]}))
