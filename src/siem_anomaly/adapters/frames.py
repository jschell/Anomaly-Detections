"""Normalize supported dataframe/table inputs to Polars."""

from typing import TypeAlias

import pandas as pd
import polars as pl
import pyarrow as pa

TabularData: TypeAlias = pd.DataFrame | pl.DataFrame | pa.Table


def to_polars(data: TabularData) -> pl.DataFrame:
    """Convert a supported in-memory tabular object to a Polars DataFrame."""
    if isinstance(data, pl.DataFrame):
        return data
    if isinstance(data, pa.Table):
        return pl.from_arrow(data)
    if isinstance(data, pd.DataFrame):
        return pl.from_pandas(data)
    raise TypeError(f"Unsupported tabular input: {type(data)!r}")
