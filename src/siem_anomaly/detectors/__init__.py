"""Explainable detector registry and execution."""

from siem_anomaly.detectors.registry import DetectorRegistry, build_default_registry

__all__ = ["DetectorRegistry", "build_default_registry"]
