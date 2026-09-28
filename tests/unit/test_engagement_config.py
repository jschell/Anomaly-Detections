from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from siem_anomaly import open_engagement


def test_open_creates_and_reuses_versioned_engagement_config(tmp_path: Path) -> None:
    root = tmp_path / "anomaly"
    first = open_engagement(root)
    assert first.paths.config.exists()
    assert first.config.schema_version == "1"
    assert first.policy.investigating_retention_days == 14

    payload = yaml.safe_load(first.paths.config.read_text(encoding="utf-8"))
    payload["evidence"]["investigating"]["retention_days"] = 21
    first.paths.config.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")

    reopened = open_engagement(root)
    assert reopened.policy.investigating_retention_days == 21
    assert reopened.policy.describe()["ordinary_raw_telemetry"] == "prohibited"


def test_invalid_or_unknown_config_fails_closed(tmp_path: Path) -> None:
    root = tmp_path / "anomaly"
    root.mkdir()
    (root / "config.yaml").write_text(
        'schema_version: "1"\nevidence:\n  investigating:\n'
        "    enabled: true\n    retention_days: 0\n  unexpected: true\n",
        encoding="utf-8",
    )
    with pytest.raises(ValidationError):
        open_engagement(root)
