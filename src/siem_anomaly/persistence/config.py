"""Versioned engagement policy configuration."""

from pathlib import Path
from typing import Literal

import yaml
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
            yaml.safe_dump(config.model_dump(mode="json"), sort_keys=False),
            encoding="utf-8",
        )
        return config
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Engagement config must contain a YAML mapping")
    return EngagementConfig.model_validate(payload)
