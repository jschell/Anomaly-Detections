import pandas as pd
import polars as pl
import pyarrow as pa

from siem_anomaly.adapters import to_polars


def test_to_polars_accepts_supported_inputs() -> None:
    records = {"value": [1, 2]}
    assert to_polars(pl.DataFrame(records)).height == 2
    assert to_polars(pd.DataFrame(records)).height == 2
    assert to_polars(pa.table(records)).height == 2
