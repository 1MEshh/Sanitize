"""OASIS SARIF v2.1.0 and ASCII terminal report formatters.

Generates standard static analysis interchange format (SARIF v2.1.0) JSON for
DevSecOps CI/CD pipelines (GitHub Code Scanning, GitLab SAST, SonarQube) and
high-contrast terminal tables with ANSI color highlighting.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Optional, Sequence

from sanitize_guard.pii_engine import PIIFinding, RuleID, Severity

SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
TOOL_NAME = "sanitize-guard"
TOOL_VERSION = "1.0.0"
TOOL_HOMEPAGE = "https://github.com/1MEshh/Sanitize"

# Mapping from RuleID to rule definitions
RULE_METADATA = {
    RuleID.MACHINE_PATH.value: {
        "id": RuleID.MACHINE_PATH.value,
        "name": "MachineSpecificPathLeak",
        "shortDescription": {"text": "Machine-specific filesystem path leak (/home/<user>, /Users/<user>)"},
        "fullDescription": {"text": "Hardcoded local filesystem paths reveal OS usernames and machine directory structure."},
        "defaultConfiguration": {"level": "error"},
    },
    RuleID.OS_USERNAME.value: {
        "id": RuleID.OS_USERNAME.value,
        "name": "OSUsernameLeak",
        "shortDescription": {"text": "Local OS username exposed in repository files"},
        "fullDescription": {"text": "System username leaks reveal workstation identities and corporate username schemes."},
        "defaultConfiguration": {"level": "warning"},
    },
    RuleID.HOSTNAME.value: {
        "id": RuleID.HOSTNAME.value,
        "name": "LocalHostnameLeak",
        "shortDescription": {"text": "Internal workstation or server hostname leak"},
        "fullDescription": {"text": "Hostnames disclose internal network topologies and naming conventions."},
        "defaultConfiguration": {"level": "warning"},
    },
    RuleID.RFC1918_PRIVATE_IP.value: {
        "id": RuleID.RFC1918_PRIVATE_IP.value,
        "name": "RFC1918PrivateIPLeak",
        "shortDescription": {"text": "RFC 1918 private IPv4 address exposed"},
        "fullDescription": {"text": "Internal private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) expose private infrastructure."},
        "defaultConfiguration": {"level": "warning"},
    },
    RuleID.RFC5737_DOC_IP.value: {
        "id": RuleID.RFC5737_DOC_IP.value,
        "name": "RFC5737DocumentationIP",
        "shortDescription": {"text": "Safe RFC 5737 documentation network IP"},
        "fullDescription": {"text": "Documentation IPs (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are safe for public templates."},
        "defaultConfiguration": {"level": "note"},
    },
    RuleID.PUBLIC_IP.value: {
        "id": RuleID.PUBLIC_IP.value,
        "name": "PublicIPAddress",
        "shortDescription": {"text": "Public IPv4 address detected"},
        "fullDescription": {"text": "Public IP addresses should be reviewed to prevent unintended endpoint exposure."},
        "defaultConfiguration": {"level": "note"},
    },
    RuleID.MAC_ADDRESS.value: {
        "id": RuleID.MAC_ADDRESS.value,
        "name": "HardwareMACAddressLeak",
        "shortDescription": {"text": "Hardware MAC address (EUI-48) leak"},
        "fullDescription": {"text": "Hardware MAC addresses uniquely identify local network interfaces and Wi-Fi chipsets."},
        "defaultConfiguration": {"level": "warning"},
    },
    RuleID.PRIVATE_KEY.value: {
        "id": RuleID.PRIVATE_KEY.value,
        "name": "CryptographicPrivateKey",
        "shortDescription": {"text": "Cryptographic private key detected in repository"},
        "fullDescription": {"text": "Committed private keys (RSA, EC, OPENSSH, PGP) compromise cryptographic identity."},
        "defaultConfiguration": {"level": "error"},
    },
    RuleID.API_TOKEN.value: {
        "id": RuleID.API_TOKEN.value,
        "name": "APITokenCredentialLeak",
        "shortDescription": {"text": "API token or authentication credential detected"},
        "fullDescription": {"text": "API keys (GitHub, AWS, OpenAI, Slack) allow unauthorized access to third-party services."},
        "defaultConfiguration": {"level": "error"},
    },
    "SAN-010": {
        "id": "SAN-010",
        "name": "MediaMetadataChunkLeak",
        "shortDescription": {"text": "Image binary contains un-stripped metadata chunks or EXIF GPS data"},
        "fullDescription": {"text": "Media files contain camera models, GPS geolocation, and timestamps in PNG/JPEG/GIF metadata."},
        "defaultConfiguration": {"level": "warning"},
    },
}


class SARIFExporter:
    """Exports PII and privacy findings to standard OASIS SARIF v2.1.0 format."""

    @staticmethod
    def _severity_to_sarif_level(severity: Severity) -> str:
        if severity in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if severity == Severity.MEDIUM:
            return "warning"
        return "note"

    @classmethod
    def generate_sarif(cls, findings: Sequence[PIIFinding]) -> dict:
        """Converts findings into standard SARIF dictionary."""
        # Aggregate unique rules present in findings
        rule_ids = {f.rule_id.value for f in findings if f.rule_id.value in RULE_METADATA}
        if not rule_ids:
            rule_ids = set(RULE_METADATA.keys())

        rules = [RULE_METADATA[rid] for rid in sorted(rule_ids)]

        results = []
        for f in findings:
            sarif_result = {
                "ruleId": f.rule_id.value,
                "level": cls._severity_to_sarif_level(f.severity),
                "message": {"text": f.description},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file_path},
                            "region": {
                                "startLine": max(1, f.line_number),
                                "startColumn": max(1, f.column),
                            },
                        }
                    }
                ],
            }
            results.append(sarif_result)

        return {
            "$schema": SARIF_SCHEMA_URI,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": TOOL_NAME,
                            "version": TOOL_VERSION,
                            "informationUri": TOOL_HOMEPAGE,
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

    @classmethod
    def to_json(cls, findings: Sequence[PIIFinding], indent: int = 2) -> str:
        """Serializes findings into formatted SARIF JSON string."""
        return json.dumps(cls.generate_sarif(findings), indent=indent)


class ASCIITableExporter:
    """Renders high-contrast, professional ASCII tables with ANSI highlighting."""

    # ANSI escape color codes
    C_RESET = "\033[0m"
    C_BOLD = "\033[1m"
    C_RED = "\033[31m"
    C_GREEN = "\033[32m"
    C_YELLOW = "\033[33m"
    C_BLUE = "\033[34m"
    C_MAGENTA = "\033[35m"
    C_CYAN = "\033[36m"
    C_GRAY = "\033[90m"

    def __init__(self, no_color: bool = False) -> None:
        env_no_color = bool(os.environ.get("NO_COLOR"))
        self.use_color = not no_color and not env_no_color and sys.stdout.isatty()

    def _color(self, text: str, color_code: str) -> str:
        if not self.use_color:
            return text
        return f"{color_code}{text}{self.C_RESET}"

    def format_table(self, findings: Sequence[PIIFinding]) -> str:
        """Formats finding sequence into clean terminal table."""
        if not findings:
            clean_banner = [
                "+------------------------------------------------------------------------+",
                "| [STATUS: SANITIZED] Zero PII, machine paths, or credentials detected.  |",
                "+------------------------------------------------------------------------+",
            ]
            msg = "\n".join(clean_banner)
            return self._color(msg, self.C_GREEN)

        headers = ["Rule ID", "Severity", "Location", "Matched Snippet", "Description"]
        rows: list[list[str]] = []

        for f in findings:
            loc = f"{f.file_path}:{f.line_number}:{f.column}"
            if len(loc) > 32:
                loc = "..." + loc[-29:]

            snippet = f.matched_text.replace("\n", " ").replace("\r", "")
            if len(snippet) > 28:
                snippet = snippet[:25] + "..."

            desc = f.description
            if len(desc) > 36:
                desc = desc[:33] + "..."

            rows.append([f.rule_id.value, f.severity.value, loc, snippet, desc])

        # Calculate max column widths
        widths = [len(h) for h in headers]
        for row in rows:
            for i, cell in enumerate(row):
                widths[i] = max(widths[i], len(cell))

        # Build box
        def make_separator(char: str = "-") -> str:
            parts = [char * (w + 2) for w in widths]
            return "+" + "+".join(parts) + "+"

        lines: list[str] = [make_separator("-")]

        # Header row
        hdr_cells = [f" {h.ljust(widths[i])} " for i, h in enumerate(headers)]
        lines.append("|" + "|".join(hdr_cells) + "|")
        lines.append(make_separator("="))

        # Data rows
        for idx, (f, row) in enumerate(zip(findings, rows)):
            sev = f.severity
            if sev == Severity.CRITICAL:
                sev_str = self._color(row[1].ljust(widths[1]), self.C_RED + self.C_BOLD)
            elif sev == Severity.HIGH:
                sev_str = self._color(row[1].ljust(widths[1]), self.C_RED)
            elif sev == Severity.MEDIUM:
                sev_str = self._color(row[1].ljust(widths[1]), self.C_YELLOW)
            elif sev == Severity.LOW:
                sev_str = self._color(row[1].ljust(widths[1]), self.C_CYAN)
            else:
                sev_str = self._color(row[1].ljust(widths[1]), self.C_GRAY)

            cell0 = f" {row[0].ljust(widths[0])} "
            cell1 = f" {sev_str} "
            cell2 = f" {row[2].ljust(widths[2])} "
            cell3 = f" {row[3].ljust(widths[3])} "
            cell4 = f" {row[4].ljust(widths[4])} "

            lines.append(f"|{cell0}|{cell1}|{cell2}|{cell3}|{cell4}|")

        lines.append(make_separator("-"))

        # Summary statistics
        counts: dict[Severity, int] = {s: 0 for s in Severity}
        for f in findings:
            counts[f.severity] += 1

        summary = (
            f"Total Findings: {len(findings)} | "
            f"Critical: {counts[Severity.CRITICAL]} | "
            f"High: {counts[Severity.HIGH]} | "
            f"Medium: {counts[Severity.MEDIUM]} | "
            f"Low: {counts[Severity.LOW]} | "
            f"Info: {counts[Severity.INFO]}"
        )
        lines.append(summary)

        return "\n".join(lines)
