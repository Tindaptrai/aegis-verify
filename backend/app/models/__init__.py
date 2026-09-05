"""Vendor-neutral event contracts for all AEGIS connectors."""

from .canonical_event import CanonicalEvent, EventAction, SourceType

__all__ = ["CanonicalEvent", "EventAction", "SourceType"]
