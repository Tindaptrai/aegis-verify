"""Vendor-neutral event contracts for all AEGIS connectors."""

from .canonical_event import CanonicalEvent, EventAction, SourceType
from .scenario import (
    ExpectedOutcome, ScenarioAssertion, ScenarioManifest, ScenarioSafety, ScenarioSource,
)

__all__ = [
    "CanonicalEvent", "EventAction", "SourceType", "ExpectedOutcome",
    "ScenarioAssertion", "ScenarioManifest", "ScenarioSafety", "ScenarioSource",
]
