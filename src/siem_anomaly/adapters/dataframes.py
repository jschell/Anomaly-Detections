from __future__ import annotations

import pandas as pd
import polars as pl
import pyarrow as pa

SupportedFrame = pd.DataFrame | pl.DataFrame | pa.Table


def to_polars(frame: SupportedFrame) -> pl.DataFrame:
    if isinstance(frame, pl.DataFrame):
        return frame.clone()
    if isinstance(frame, pd.DataFrame):
        return pl.from_pandas(frame)
    if isinstance(frame, pa.Table):
        return pl.from_arrow(frame)
    raise TypeError(f"Unsupported dataframe type: {type(frame)!r}")


def columns(frame: SupportedFrame) -> tuple[str, ...]:
    if isinstance(frame, pd.DataFrame):
        return tuple(str(column) for column in frame.columns)
    if isinstance(frame, pl.DataFrame):
        return tuple(frame.columns)
    if isinstance(frame, pa.Table):
        return tuple(frame.column_names)
    raise TypeError(f"Unsupported dataframe type: {type(frame)!r}")
