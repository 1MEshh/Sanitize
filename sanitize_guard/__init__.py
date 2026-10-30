"""Sanitize Guard: Zero-dependency DevSecOps & Privacy Engineering Toolkit.

Provides automated PII detection, pure-Python binary media metadata chunk scrubbing,
dotfile template sanitization, and git commit-graph forensics.
"""

from __future__ import annotations

__version__ = "1.1.0"

from sanitize_guard.dotfile_redactor import (
    DotfileRedactor,
    RedactionChange,
    RedactionResult,
)
from sanitize_guard.media_scrubber import (
    SUPPORTED_EXTENSIONS,
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
    SanitizeIgnore,
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
    "SanitizeIgnore",
    "RFC5737_NETWORKS",
    "RFC1918_NETWORKS",
    "RFC3849_NETWORK",
    "GENERIC_USER_PLACEHOLDERS",
    "GENERIC_HOSTNAMES",
    "MediaScrubber",
    "SUPPORTED_EXTENSIONS",
    "MetadataChunkInfo",
    "ScrubResult",
    "DotfileRedactor",
    "RedactionChange",
    "RedactionResult",
    "SARIFExporter",
    "ASCIITableExporter",
]
