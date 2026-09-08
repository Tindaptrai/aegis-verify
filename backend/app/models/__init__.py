"""Vendor-neutral event contracts for all AEGIS connectors."""

from .canonical_event import CanonicalEvent, EventAction, SourceType
from .canonical_event_v2 import CanonicalEventV2
from .precise_timestamp import PreciseTimestamp
from .scenario import (
    ExpectedOutcome, ScenarioAssertion, ScenarioManifest, ScenarioSafety, ScenarioSource,
)

__all__ = [
    "CanonicalEvent", "CanonicalEventV2", "PreciseTimestamp", "EventAction", "SourceType", "ExpectedOutcome",
    "ScenarioAssertion", "ScenarioManifest", "ScenarioSafety", "ScenarioSource",
]
