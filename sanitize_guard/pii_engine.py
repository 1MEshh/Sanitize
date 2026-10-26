"""PII and local environment leakage detection engine.

Scans text streams, source code, configuration files, and git history for:
- Machine-specific filesystem paths (/home/<user>, /Users/<user>, C:\\Users\\<user>)
- Current and targeted OS usernames
- Local network hostnames
- RFC 1918 private IPv4 addresses vs RFC 5737 documentation networks
- Hardware MAC addresses (EUI-48)
- Cryptographic private keys (RSA, EC, DSA, OPENSSH, PGP)
- API tokens, credentials, and access secrets
"""

from __future__ import annotations

import getpass
import ipaddress
import os
import re
import socket
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Optional, Sequence


class Severity(str, Enum):
    """Severity ratings for security and privacy findings."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class RuleID(str, Enum):
    """Canonical rule identifiers for SARIF and audit categorization."""
    MACHINE_PATH = "SAN-001"
    OS_USERNAME = "SAN-002"
    HOSTNAME = "SAN-003"
    RFC1918_PRIVATE_IP = "SAN-004"
    RFC5737_DOC_IP = "SAN-005"
    PUBLIC_IP = "SAN-006"
    MAC_ADDRESS = "SAN-007"
    PRIVATE_KEY = "SAN-008"
    API_TOKEN = "SAN-009"


@dataclass(frozen=True)
class PIIFinding:
    """Represents an atomic detection of a privacy or credential leak."""
    rule_id: RuleID
    severity: Severity
    description: str
    file_path: str
    line_number: int
    column: int
    matched_text: str
    replacement: Optional[str] = None
    is_leak: bool = True

    def to_dict(self) -> dict:
        """Serializes finding to a standard dictionary representation."""
        return {
            "rule_id": self.rule_id.value,
            "severity": self.severity.value,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "matched_text": self.matched_text,
            "replacement": self.replacement,
            "is_leak": self.is_leak,
        }


# RFC 5737 IPv4 Documentation Networks (Safe for public release)
RFC5737_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
)

# RFC 3849 IPv6 Documentation Network
RFC3849_NETWORK = ipaddress.ip_network("2001:db8::/32")

# RFC 1918 Private IPv4 Networks & CGNAT
RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),     # RFC 6598 Shared Carrier-Grade NAT
)

# Standard placeholders recognized as intentional template variables
GENERIC_USER_PLACEHOLDERS = {
    "<user>",
    "<username>",
    "user",
    "username",
    "your_user",
    "your_username",
    "runner",
    "example",
    "dummy",
    "synthetic_user",
    "synthuser",
    "devuser",
}

# Generic hostname values that do not leak private identity
GENERIC_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "ubuntu",
    "debian",
    "fedora",
    "archlinux",
    "arch",
    "nixos",
    "runner",
    "actions",
    "docker",
}


class PIIEngine:
    """Core regex and heuristic privacy scanner."""

    # Pre-compiled high-performance regular expressions
    _RE_LINUX_HOME = re.compile(
        r"(?:^|(?<=[\s'\"`=:(/]))(/home/([a-zA-Z0-9_.-]+)(?:/[^\s'\"`:,;()\[\]<>]*)?)"
    )
    _RE_MACOS_USERS = re.compile(
        r"(?:^|(?<=[\s'\"`=:(/]))(/Users/([a-zA-Z0-9_.-]+)(?:/[^\s'\"`:,;()\[\]<>]*)?)"
    )
    _RE_WINDOWS_USERS = re.compile(
        r"(?:^|(?<=[\s'\"`=:(]))([a-zA-Z]:[/\\]Users[/\\]([a-zA-Z0-9_.-]+)(?:[/\\][^\s'\"`:,;()\[\]<>]*)?)"
    )

    _RE_IPV4 = re.compile(
        r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    )

    _RE_MAC = re.compile(
        r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"
    )

    _RE_PRIVATE_KEY = re.compile(
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY(?: BLOCK)?-----"
    )

    _RE_GH_TOKEN = re.compile(
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b"
    )

    _RE_AWS_KEY = re.compile(
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    )

    _RE_SK_TOKEN = re.compile(
        r"\bsk-(?:live_|test_|ant-)?[A-Za-z0-9_-]{20,}\b"
    )

    _RE_SLACK_TOKEN = re.compile(
        r"\bxox[baprs]-[A-Za-z0-9-]{24,}\b"
    )

    _RE_GENERIC_SECRET = re.compile(
        r"(?i)\b(?:api_key|apikey|secret_key|secret|password|access_token|auth_token)\s*[:=]\s*['\"]([A-Za-z0-9_\-\.\$\#\@\%]{10,})['\"]"
    )

    def __init__(
        self,
        target_usernames: Optional[Sequence[str]] = None,
        target_hostnames: Optional[Sequence[str]] = None,
        auto_detect_system: bool = True,
        ignored_rules: Optional[Sequence[RuleID]] = None,
    ) -> None:
        """Initializes the engine with dynamic and target identity parameters."""
        self.ignored_rules: set[RuleID] = set(ignored_rules or [])
        self.target_usernames: set[str] = set(target_usernames or [])
        self.target_hostnames: set[str] = set(target_hostnames or [])

        if auto_detect_system:
            try:
                curr_user = getpass.getuser().strip()
                if curr_user and curr_user not in {"root", "runner", "none", "nobody"}:
                    self.target_usernames.add(curr_user)
            except Exception:
                pass

            try:
                curr_host = socket.gethostname().strip()
                if curr_host and curr_host.lower() not in GENERIC_HOSTNAMES:
                    self.target_hostnames.add(curr_host)
            except Exception:
                pass

        # Build dynamic word-boundary regexes for target usernames and hostnames
        self._user_regexes: list[tuple[str, re.Pattern]] = [
            (u, re.compile(rf"(?<![a-zA-Z0-9_.-]){re.escape(u)}(?![a-zA-Z0-9_.-])"))
            for u in self.target_usernames
            if len(u) >= 2
        ]
        self._host_regexes: list[tuple[str, re.Pattern]] = [
            (h, re.compile(rf"(?<![a-zA-Z0-9_.-]){re.escape(h)}(?![a-zA-Z0-9_.-])"))
            for h in self.target_hostnames
            if len(h) >= 2
        ]

    def scan_text(self, text: str, file_path: str = "<stdin>") -> list[PIIFinding]:
        """Scans arbitrary text buffer line by line and aggregates findings."""
        findings: list[PIIFinding] = []
        for line_num, line in enumerate(text.splitlines(), start=1):
            findings.extend(self.scan_line(line, line_num=line_num, file_path=file_path))
        return findings

    def scan_line(self, line: str, line_num: int = 1, file_path: str = "<stdin>") -> list[PIIFinding]:
        """Scans a single string line for PII and privacy patterns."""
        findings: list[PIIFinding] = []
        matched_spans: set[tuple[int, int]] = set()

        def overlaps(s: int, e: int) -> bool:
            return any(not (e <= existing_s or s >= existing_e) for existing_s, existing_e in matched_spans)

        # Skip lines that are themselves redaction templates
        if "<REDACTED" in line:
            return []

        # 1. Private Keys
        if RuleID.PRIVATE_KEY not in self.ignored_rules:
            for match in self._RE_PRIVATE_KEY.finditer(line):
                start, end = match.span()
                matched_spans.add((start, end))
                findings.append(
                    PIIFinding(
                        rule_id=RuleID.PRIVATE_KEY,
                        severity=Severity.CRITICAL,
                        description="Cryptographic private key header detected",
                        file_path=file_path,
                        line_number=line_num,
                        column=start + 1,
                        matched_text=match.group(0),
                        replacement="-----BEGIN PRIVATE KEY-----\n<REDACTED_KEY_DATA>\n-----END PRIVATE KEY-----",
                        is_leak=True,
                    )
                )

        # 2. Machine-Specific Paths (/home/..., /Users/..., C:\Users\...)
        if RuleID.MACHINE_PATH not in self.ignored_rules:
            for regex in (self._RE_LINUX_HOME, self._RE_MACOS_USERS, self._RE_WINDOWS_USERS):
                for match in regex.finditer(line):
                    full_path = match.group(1)
                    user_part = match.group(2)
                    start, end = match.start(1), match.end(1)

                    # Skip template placeholders and ellipsis (...)
                    clean_user = user_part.lower().strip()
                    if (
                        clean_user in GENERIC_USER_PLACEHOLDERS
                        or clean_user in {"...", "..", "."}
                        or all(c == "." for c in clean_user)
                        or (clean_user.startswith("<") and clean_user.endswith(">"))
                    ):
                        continue

                    matched_spans.add((start, end))
                    findings.append(
                        PIIFinding(
                            rule_id=RuleID.MACHINE_PATH,
                            severity=Severity.HIGH,
                            description=f"Machine-specific filesystem path leak detected: {full_path}",
                            file_path=file_path,
                            line_number=line_num,
                            column=start + 1,
                            matched_text=full_path,
                            replacement="${HOME}" if full_path.startswith(("/home", "/Users")) else "%USERPROFILE%",
                            is_leak=True,
                        )
                    )

        # 3. API Tokens & Credentials
        if RuleID.API_TOKEN not in self.ignored_rules:
            # GitHub tokens
            for match in self._RE_GH_TOKEN.finditer(line):
                start, end = match.span()
                if not overlaps(start, end):
                    matched_spans.add((start, end))
                    findings.append(
                        PIIFinding(
                            rule_id=RuleID.API_TOKEN,
                            severity=Severity.HIGH,
                            description="GitHub personal access token detected",
                            file_path=file_path,
                            line_number=line_num,
                            column=start + 1,
                            matched_text=match.group(0),
                            replacement="ghp_<REDACTED_GITHUB_TOKEN>",
                            is_leak=True,
                        )
                    )

            # AWS access keys
            for match in self._RE_AWS_KEY.finditer(line):
                start, end = match.span()
                if not overlaps(start, end):
                    matched_spans.add((start, end))
                    findings.append(
                        PIIFinding(
                            rule_id=RuleID.API_TOKEN,
                            severity=Severity.HIGH,
                            description="AWS Access Key ID detected",
                            file_path=file_path,
                            line_number=line_num,
                            column=start + 1,
                            matched_text=match.group(0),
                            replacement="AKIA<REDACTED_AWS_KEY>",
                            is_leak=True,
                        )
                    )

            # OpenAI / Anthropic secret tokens
            for match in self._RE_SK_TOKEN.finditer(line):
                start, end = match.span()
                if not overlaps(start, end):
                    matched_spans.add((start, end))
                    findings.append(
                        PIIFinding(
                            rule_id=RuleID.API_TOKEN,
                            severity=Severity.HIGH,
                            description="OpenAI or Anthropic API secret key detected",
                            file_path=file_path,
                            line_number=line_num,
                            column=start + 1,
                            matched_text=match.group(0),
                            replacement="sk-<REDACTED_API_SECRET>",
                            is_leak=True,
                        )
                    )

            # Slack tokens
            for match in self._RE_SLACK_TOKEN.finditer(line):
                start, end = match.span()
                if not overlaps(start, end):
                    matched_spans.add((start, end))
                    findings.append(
                        PIIFinding(
                            rule_id=RuleID.API_TOKEN,
                            severity=Severity.HIGH,
                            description="Slack API token detected",
                            file_path=file_path,
                            line_number=line_num,
                            column=start + 1,
                            matched_text=match.group(0),
                            replacement="xoxb-<REDACTED_SLACK_TOKEN>",
                            is_leak=True,
                        )
                    )

            # Generic secrets
            for match in self._RE_GENERIC_SECRET.finditer(line):
                secret_val = match.group(1)
                start, end = match.start(1), match.end(1)
                if not overlaps(start, end) and not secret_val.startswith("<REDACTED"):
                    matched_spans.add((start, end))
                    findings.append(
                        PIIFinding(
                            rule_id=RuleID.API_TOKEN,
                            severity=Severity.HIGH,
                            description="Hardcoded authentication credential / secret detected",
                            file_path=file_path,
                            line_number=line_num,
                            column=start + 1,
                            matched_text=secret_val,
                            replacement="<REDACTED_SECRET>",
                            is_leak=True,
                        )
                    )

        # 4. IP Addresses (RFC 1918 Private vs RFC 5737 Documentation vs Public)
        for match in self._RE_IPV4.finditer(line):
            start, end = match.span()
            if overlaps(start, end):
                continue

            ip_str = match.group(0)
            try:
                ip = ipaddress.ip_address(ip_str)
            except ValueError:
                continue

            # Check if this IP is part of a CIDR network mask declaration (e.g. 10.0.0.0/8)
            is_cidr_declaration = bool(re.match(r"^/\d{1,2}\b", line[end:]))

            # Check RFC 5737 Documentation IP (TEST-NET-1, TEST-NET-2, TEST-NET-3)
            if any(ip in net for net in RFC5737_NETWORKS):
                if RuleID.RFC5737_DOC_IP not in self.ignored_rules:
                    matched_spans.add((start, end))
                    findings.append(
                        PIIFinding(
                            rule_id=RuleID.RFC5737_DOC_IP,
                            severity=Severity.INFO,
                            description=f"RFC 5737 Documentation IPv4 address (Safe): {ip_str}",
                            file_path=file_path,
                            line_number=line_num,
                            column=start + 1,
                            matched_text=ip_str,
                            replacement=None,
                            is_leak=False,
                        )
                    )
                continue

            # Check RFC 1918 Private IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10)
            if any(ip in net for net in RFC1918_NETWORKS):
                if RuleID.RFC1918_PRIVATE_IP not in self.ignored_rules:
                    matched_spans.add((start, end))
                    if is_cidr_declaration:
                        findings.append(
                            PIIFinding(
                                rule_id=RuleID.RFC1918_PRIVATE_IP,
                                severity=Severity.INFO,
                                description=f"RFC 1918 Subnet CIDR specification: {ip_str}",
                                file_path=file_path,
                                line_number=line_num,
                                column=start + 1,
                                matched_text=ip_str,
                                replacement=None,
                                is_leak=False,
                            )
                        )
                    else:
                        # Deterministic safe mapping: last octet preserved in 198.51.100.0/24
                        last_octet = int(ip_str.split(".")[-1])
                        safe_replacement = f"198.51.100.{last_octet}"
                        findings.append(
                            PIIFinding(
                                rule_id=RuleID.RFC1918_PRIVATE_IP,
                                severity=Severity.MEDIUM,
                                description=f"RFC 1918 Private IPv4 address leak: {ip_str}",
                                file_path=file_path,
                                line_number=line_num,
                                column=start + 1,
                                matched_text=ip_str,
                                replacement=safe_replacement,
                                is_leak=True,
                            )
                        )
                continue

            # Check Loopback (127.0.0.0/8)
            if ip.is_loopback:
                # Loopback is informational / safe
                continue

            # Check Public IP
            if ip.is_global:
                if RuleID.PUBLIC_IP not in self.ignored_rules:
                    matched_spans.add((start, end))
                    findings.append(
                        PIIFinding(
                            rule_id=RuleID.PUBLIC_IP,
                            severity=Severity.LOW,
                            description=f"Public IPv4 address detected: {ip_str}",
                            file_path=file_path,
                            line_number=line_num,
                            column=start + 1,
                            matched_text=ip_str,
                            replacement="198.51.100.1",
                            is_leak=True,
                        )
                    )

        # 5. Hardware MAC Addresses
        if RuleID.MAC_ADDRESS not in self.ignored_rules:
            for match in self._RE_MAC.finditer(line):
                start, end = match.span()
                if overlaps(start, end):
                    continue

                mac_str = match.group(0)
                norm_mac = mac_str.replace("-", ":").lower()
                # Exclude all-zeros, broadcast, and standard documentation dummy MAC
                if norm_mac in {"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "02:00:00:00:00:01"}:
                    continue

                matched_spans.add((start, end))
                findings.append(
                    PIIFinding(
                        rule_id=RuleID.MAC_ADDRESS,
                        severity=Severity.MEDIUM,
                        description=f"Hardware MAC address leak detected: {mac_str}",
                        file_path=file_path,
                        line_number=line_num,
                        column=start + 1,
                        matched_text=mac_str,
                        replacement="02:00:00:00:00:01",
                        is_leak=True,
                    )
                )

        # 6. Target OS Usernames
        if RuleID.OS_USERNAME not in self.ignored_rules:
            for username, regex in self._user_regexes:
                for match in regex.finditer(line):
                    start, end = match.span()
                    if not overlaps(start, end):
                        matched_spans.add((start, end))
                        findings.append(
                            PIIFinding(
                                rule_id=RuleID.OS_USERNAME,
                                severity=Severity.MEDIUM,
                                description=f"Local OS username leak detected: {username}",
                                file_path=file_path,
                                line_number=line_num,
                                column=start + 1,
                                matched_text=match.group(0),
                                replacement="<user>",
                                is_leak=True,
                            )
                        )

        # 7. Target Hostnames
        if RuleID.HOSTNAME not in self.ignored_rules:
            for hostname, regex in self._host_regexes:
                for match in regex.finditer(line):
                    start, end = match.span()
                    if not overlaps(start, end):
                        matched_spans.add((start, end))
                        findings.append(
                            PIIFinding(
                                rule_id=RuleID.HOSTNAME,
                                severity=Severity.MEDIUM,
                                description=f"Local machine hostname leak detected: {hostname}",
                                file_path=file_path,
                                line_number=line_num,
                                column=start + 1,
                                matched_text=match.group(0),
                                replacement="localhost",
                                is_leak=True,
                            )
                        )

        return findings

    def scan_file(self, file_path: str | Path) -> list[PIIFinding]:
        """Reads a file from disk and performs comprehensive PII scanning."""
        path = Path(file_path)
        if not path.is_file():
            return []

        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        return self.scan_text(content, file_path=str(path))

    def scan_directory(
        self,
        directory: str | Path,
        ignore_patterns: Optional[Sequence[str]] = None,
    ) -> list[PIIFinding]:
        """Recursively scans directory tree while honoring ignore patterns."""
        root = Path(directory)
        if not root.exists():
            return []

        patterns = list(ignore_patterns or [
            ".git",
            "__pycache__",
            ".venv",
            "venv",
            "node_modules",
            "*.pyc",
            "*.png",
            "*.jpg",
            "*.jpeg",
            "*.gif",
            "*.ico",
            "*.pdf",
        ])

        findings: list[PIIFinding] = []
        for curr_root, dirs, files in os.walk(root):
            # Prune ignored directories
            dirs[:] = [
                d for d in dirs
                if not any(re.search(rf"\b{re.escape(d)}\b", p) for p in patterns)
                and not d.startswith(".")
            ]

            for f in files:
                filepath = Path(curr_root) / f
                # Check file ignore pattern
                rel_path = str(filepath.relative_to(root))
                if any(filepath.match(p) or rel_path == p for p in patterns):
                    continue

                # Only scan text-like files
                if f.endswith((".py", ".sh", ".bash", ".zsh", ".conf", ".cfg", ".ini", ".json", ".yaml", ".yml", ".toml", ".md", ".txt", ".env", ".template", ".xml", ".svg")):
                    findings.extend(self.scan_file(filepath))

        return findings
