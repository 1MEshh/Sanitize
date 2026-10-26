"""Sanitize Guard: Zero-dependency DevSecOps & Privacy Engineering Toolkit.

Provides automated PII detection, pure-Python binary media metadata chunk scrubbing,
dotfile template sanitization, and git commit-graph forensics.
"""

from __future__ import annotations

__version__ = "1.0.0"

from sanitize_guard.dotfile_redactor import (
    DotfileRedactor,
    RedactionChange,
    RedactionResult,
)
from sanitize_guard.media_scrubber import (
    MediaScrubber,
    MetadataChunkInfo,
    ScrubResult,
)
from sanitize_guard.pii_engine import (
    GENERIC_HOSTNAMES,
    GENERIC_USER_PLACEHOLDERS,
    RFC1918_NETWORKS,
    RFC3849_NETWORK,
    RFC5737_NETWORKS,
    PIIEngine,
    PIIFinding,
    RuleID,
    Severity,
)
from sanitize_guard.sarif import (
    ASCIITableExporter,
    SARIFExporter,
)

__all__ = [
    "__version__",
    "Severity",
    "RuleID",
    "PIIFinding",
    "PIIEngine",
    "RFC5737_NETWORKS",
    "RFC1918_NETWORKS",
    "RFC3849_NETWORK",
    "GENERIC_USER_PLACEHOLDERS",
    "GENERIC_HOSTNAMES",
    "MediaScrubber",
    "MetadataChunkInfo",
    "ScrubResult",
    "DotfileRedactor",
    "RedactionChange",
    "RedactionResult",
    "SARIFExporter",
    "ASCIITableExporter",
]
