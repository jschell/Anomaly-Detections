import pandas as pd
import polars as pl
import pyarrow as pa

from siem_anomaly.adapters import to_polars


def test_to_polars_supports_pandas_polars_and_arrow() -> None:
    pandas_frame = pd.DataFrame({"a": [1, 2]})
    polars_frame = pl.DataFrame({"a": [1, 2]})
    arrow_table = pa.table({"a": [1, 2]})

    assert to_polars(pandas_frame).to_dict(as_series=False) == {"a": [1, 2]}
    assert to_polars(polars_frame).to_dict(as_series=False) == {"a": [1, 2]}
    assert to_polars(arrow_table).to_dict(as_series=False) == {"a": [1, 2]}
