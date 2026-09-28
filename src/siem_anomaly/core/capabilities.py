"""Semantic capabilities exposed by source adapters."""

from dataclasses import dataclass
from enum import StrEnum


class Capability(StrEnum):
    TIMESTAMP = "timestamp"
    ACTOR = "actor"
    ACTOR_TYPE = "actor_type"
    ACTION = "action"
    TARGET = "target"
    SOURCE_IP = "source_ip"
    APPLICATION = "application"
    OUTCOME = "outcome"
    REGION = "region"
    DEVICE = "device"
    AUTHENTICATION = "authentication"
    COUNTRY = "country"


@dataclass(frozen=True, slots=True)
class FieldBinding:
    """Maps a provider field to a canonical semantic capability."""

    canonical_name: str
    source_field: str
    capability: Capability
    semantic_role: str
    required: bool = False
