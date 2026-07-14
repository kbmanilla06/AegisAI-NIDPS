"""Strict, bounded telemetry normalization for Sprint 2."""

from aegis_services.ingestion.adapters import FatalIngestionError, ParseLimits, parse_file
from aegis_services.ingestion.schema import CanonicalFlowV1, ParsedRecord, event_key

__all__ = [
    "CanonicalFlowV1",
    "FatalIngestionError",
    "ParseLimits",
    "ParsedRecord",
    "event_key",
    "parse_file",
]
