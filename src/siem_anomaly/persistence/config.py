"""Versioned engagement policy configuration.

JSON is emitted into config.yaml. JSON is valid YAML 1.2, which keeps the
configuration human-readable without adding a runtime YAML dependency.
"""

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class InvestigatingEvidenceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    retention_days: int = Field(default=14, ge=1)


class IncidentEvidenceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    retention: Literal["engagement"] = "engagement"


class EvidenceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    investigating: InvestigatingEvidenceConfig = InvestigatingEvidenceConfig()
    incident: IncidentEvidenceConfig = IncidentEvidenceConfig()


class EngagementConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1"] = "1"
    evidence: EvidenceConfig = EvidenceConfig()


def default_config() -> EngagementConfig:
    return EngagementConfig()


def load_or_create_config(path: Path) -> EngagementConfig:
    """Create a conservative config once, otherwise validate without rewriting it."""
    if not path.exists():
        config = default_config()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(config.model_dump(mode="json"), indent=2, sort_keys=False) + "\n",
            encoding="utf-8",
        )
        return config
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Engagement config must contain a mapping")
    return EngagementConfig.model_validate(payload)
