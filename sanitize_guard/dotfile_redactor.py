"""Dotfile sanitizer and public template generator.

Transforms live personal environment dotfiles (.zshrc, .bashrc, .gitconfig,
hyprland.conf, .env, .ssh/config) into safe public templates with placeholders.
Redacts personal identity, real user home paths, private IP addresses, MACs,
and secret credentials while preserving configuration structure and comments.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

from sanitize_guard.pii_engine import (
    GENERIC_USER_PLACEHOLDERS,
    RFC1918_NETWORKS,
    PIIEngine,
    RuleID,
    Severity,
)


@dataclass(frozen=True)
class RedactionChange:
    """Details of a single redaction substitution applied to a file."""
    line_number: int
    original: str
    redacted: str
    reason: str


@dataclass(frozen=True)
class RedactionResult:
    """Outcome of dotfile redaction."""
    file_path: str
    original_content: str
    redacted_content: str
    changes: list[RedactionChange]
    is_modified: bool

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "is_modified": self.is_modified,
            "total_changes": len(self.changes),
            "changes": [
                {
                    "line_number": c.line_number,
                    "original": c.original,
                    "redacted": c.redacted,
                    "reason": c.reason,
                }
                for c in self.changes
            ],
        }


class DotfileRedactor:
    """Intelligent template generator and dotfile sanitizer."""

    _RE_HOME_PATH = re.compile(
        r"(/home/([a-zA-Z0-9_.-]+)(?:/([^\s'\"`:,;()\[\]<>]*))?)"
    )
    _RE_MACOS_PATH = re.compile(
        r"(/Users/([a-zA-Z0-9_.-]+)(?:/([^\s'\"`:,;()\[\]<>]*))?)"
    )
    _RE_GIT_USER_SECTION = re.compile(
        r"\[user\]\s*([^\[]+)", re.MULTILINE
    )
    _RE_HYPR_MONITOR_DESC = re.compile(
        r"(monitor\s*=\s*desc:)([^,\n]+)"
    )
    _RE_HYPR_DEVICE = re.compile(
        r"(device\s*:\s*)([a-zA-Z0-9_.-]+:[a-zA-Z0-9_.-]+)"
    )
    _RE_SSH_HOSTNAME = re.compile(
        r"(?i)(HostName\s+)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    )
    _RE_WEATHER_QUERY_KEY = re.compile(
        r"(?i)([?&](?:appid|api_key|apikey|key)=)([A-Za-z0-9_-]{8,})"
    )
    _RE_WEATHER_ENV_KEY = re.compile(
        r"(?i)(\b(?:WEATHER_API_KEY|OWM_API_KEY|OPENWEATHER_API_KEY|WEATHERAPI_KEY|api[-_]?key)\b\s*[:=]\s*['\"]?)([A-Za-z0-9_-]{8,})(['\"]?)"
    )
    _RE_GEO_QUERY_COORD = re.compile(
        r"(?i)([?&](?:lat|latitude|lon|lng|longitude)=)(-?\d{1,3}(?:\.\d+)?)"
    )
    _RE_GEO_VAR_COORD = re.compile(
        r"(?i)([\"']?\b(?:lat|latitude|lon|lng|longitude)\b[\"']?\s*[:=]\s*['\"]?)(-?\d{1,3}\.\d{2,})(['\"]?)"
    )
    _RE_WTTR_LOCATION = re.compile(
        r"(?i)(https?://(?:www\.)?wttr\.in/)([^?\s'\"`#]+)"
    )
    _RE_WEATHER_CITY_VAR = re.compile(
        r"(?i)([\"']?\b(?:CITY|WEATHER_CITY|LOCATION|WEATHER_LOCATION)\b[\"']?\s*[:=]\s*['\"])([^'\"<\n]{2,})(['\"])"
    )

    def __init__(
        self,
        default_git_name: str = "1MEshh",
        default_git_email: str = "152591660+1MEshh@users.noreply.github.com",
    ) -> None:
        self.default_git_name = default_git_name
        self.default_git_email = default_git_email
        self.pii_engine = PIIEngine()

    def _scrub_weather_line(
        self, curr: str, line_idx: int, changes: list[RedactionChange]
    ) -> str:
        """Scrubs weather API keys and location coordinates from Waybar scripts/configs."""
        rules: list[tuple[re.Pattern[str], str, str]] = [
            (
                self._RE_WEATHER_QUERY_KEY,
                "<REDACTED_WEATHER_API_KEY>",
                "Weather API query key scrubbed",
            ),
            (
                self._RE_WEATHER_ENV_KEY,
                "<REDACTED_WEATHER_API_KEY>",
                "Weather API key scrubbed",
            ),
            (
                self._RE_GEO_QUERY_COORD,
                "<REDACTED_COORD>",
                "Geographic coordinate scrubbed from weather URL",
            ),
            (
                self._RE_GEO_VAR_COORD,
                "<REDACTED_COORD>",
                "Geographic coordinate scrubbed from Waybar script",
            ),
            (
                self._RE_WTTR_LOCATION,
                "<REDACTED_LOCATION>",
                "Location query scrubbed from wttr.in URL",
            ),
            (
                self._RE_WEATHER_CITY_VAR,
                "<REDACTED_LOCATION>",
                "Location identifier scrubbed from Waybar script",
            ),
        ]
        for regex, placeholder, reason in rules:
            for match in list(regex.finditer(curr)):
                secret = match.group(2)
                if secret.startswith("<"):
                    continue
                suffix = match.group(3) if len(match.groups()) >= 3 else ""
                replacement = f"{match.group(1)}{placeholder}{suffix}"
                curr = curr.replace(match.group(0), replacement, 1)
                changes.append(
                    RedactionChange(
                        line_number=line_idx,
                        original=secret,
                        redacted=placeholder,
                        reason=reason,
                    )
                )
        return curr

    @staticmethod
    def _format_home_replacement(curr: str, sub_path: str, use_plain_home: bool) -> str:
        """Selects an appropriate $HOME / ~ / ${HOME} placeholder based on file context."""
        if "PATH=" in curr or "export " in curr:
            return f"${{HOME}}/{sub_path}" if sub_path else "${HOME}"
        if curr.strip().startswith(("exec-once", "source", ".")):
            return f"~/{sub_path}" if sub_path else "~"
        if use_plain_home:
            return f"$HOME/{sub_path}" if sub_path else "$HOME"
        return f"${{HOME}}/{sub_path}" if sub_path else "${HOME}"

    def redact_text(self, content: str, filename: str = "") -> RedactionResult:
        """Sanitizes text content and returns the redacted result with detailed diff."""
        lines = content.splitlines(keepends=True)
        new_lines: list[str] = []
        changes: list[RedactionChange] = []
        basename = os.path.basename(filename).lower()
        lower_path = filename.lower()

        is_gitconfig = ".gitconfig" in basename or basename == "config"
        is_hyprland = "hypr" in lower_path or basename.endswith(".conf")
        is_waybar = "waybar" in lower_path or basename.endswith((".jsonc", ".css", ".rasi"))
        is_weather_context = (
            is_waybar
            or "weather" in lower_path
            or any(
                marker in content.lower()
                for marker in ("openweathermap", "wttr.in", "weatherapi", "open-meteo", "weather_api")
            )
        )
        is_env = ".env" in basename
        is_ssh = "ssh" in filename or basename == "config"
        use_plain_home = is_hyprland or is_waybar

        for line_idx, raw_line in enumerate(lines, start=1):
            curr = raw_line
            orig = raw_line

            # 1. Redact machine home paths
            for match in self._RE_HOME_PATH.finditer(curr):
                full_path = match.group(1)
                user_part = match.group(2)
                sub_path = match.group(3) or ""

                if user_part.lower() not in GENERIC_USER_PLACEHOLDERS and not user_part.startswith("<"):
                    replacement = self._format_home_replacement(curr, sub_path, use_plain_home)
                    curr = curr.replace(full_path, replacement)
                    changes.append(
                        RedactionChange(
                            line_number=line_idx,
                            original=full_path,
                            redacted=replacement,
                            reason="Machine-specific home path sanitized",
                        )
                    )

            for match in self._RE_MACOS_PATH.finditer(curr):
                full_path = match.group(1)
                user_part = match.group(2)
                sub_path = match.group(3) or ""

                if user_part.lower() not in GENERIC_USER_PLACEHOLDERS and not user_part.startswith("<"):
                    replacement = self._format_home_replacement(curr, sub_path, use_plain_home)
                    curr = curr.replace(full_path, replacement)
                    changes.append(
                        RedactionChange(
                            line_number=line_idx,
                            original=full_path,
                            redacted=replacement,
                            reason="macOS user path sanitized",
                        )
                    )

            # 2. Redact Gitconfig identity
            if is_gitconfig or "name =" in curr or "email =" in curr:
                # Name replacement
                name_match = re.search(r"(\s*name\s*=\s*)([^\n]+)", curr)
                if name_match and not name_match.group(2).strip().startswith(self.default_git_name):
                    old_name = name_match.group(2).strip()
                    curr = curr.replace(name_match.group(0), f"{name_match.group(1)}{self.default_git_name}")
                    changes.append(
                        RedactionChange(
                            line_number=line_idx,
                            original=old_name,
                            redacted=self.default_git_name,
                            reason="Git author name sanitized to public handle",
                        )
                    )

                # Email replacement
                email_match = re.search(r"(\s*email\s*=\s*)([^\n]+)", curr)
                if email_match and not email_match.group(2).strip().endswith("noreply.github.com"):
                    old_email = email_match.group(2).strip()
                    curr = curr.replace(email_match.group(0), f"{email_match.group(1)}{self.default_git_email}")
                    changes.append(
                        RedactionChange(
                            line_number=line_idx,
                            original=old_email,
                            redacted=self.default_git_email,
                            reason="Personal git email sanitized to noreply",
                        )
                    )

                # GPG signing key
                key_match = re.search(r"(\s*signingkey\s*=\s*)([^\n]+)", curr)
                if key_match and not key_match.group(2).strip().startswith("<"):
                    old_key = key_match.group(2).strip()
                    curr = curr.replace(key_match.group(0), f"{key_match.group(1)}<YOUR_GPG_KEY_ID>")
                    changes.append(
                        RedactionChange(
                            line_number=line_idx,
                            original=old_key,
                            redacted="<YOUR_GPG_KEY_ID>",
                            reason="Personal GPG signing key ID sanitized",
                        )
                    )

            # 3. Redact RFC 1918 Private IPs -> RFC 5737 Documentation IPs
            findings = self.pii_engine.scan_line(curr, line_num=line_idx, file_path=filename)
            for f in findings:
                if f.rule_id == RuleID.RFC1918_PRIVATE_IP and f.replacement:
                    curr = curr.replace(f.matched_text, f.replacement)
                    changes.append(
                        RedactionChange(
                            line_number=line_idx,
                            original=f.matched_text,
                            redacted=f.replacement,
                            reason="RFC 1918 private IP mapped to RFC 5737 documentation network",
                        )
                    )
                elif f.rule_id == RuleID.MAC_ADDRESS and f.replacement:
                    curr = curr.replace(f.matched_text, f.replacement)
                    changes.append(
                        RedactionChange(
                            line_number=line_idx,
                            original=f.matched_text,
                            redacted=f.replacement,
                            reason="Hardware MAC address masked to safe local address",
                        )
                    )
                elif f.rule_id == RuleID.API_TOKEN and f.replacement:
                    curr = curr.replace(f.matched_text, f.replacement)
                    changes.append(
                        RedactionChange(
                            line_number=line_idx,
                            original=f.matched_text,
                            redacted=f.replacement,
                            reason="Secret API token masked with placeholder",
                        )
                    )

            # 4. Redact Environment Variables / DB URLs
            if is_env or "export " in curr or "_KEY=" in curr or "_TOKEN=" in curr or "_SECRET=" in curr:
                # Database connection string with embedded password/IP
                db_match = re.search(r"(postgres(?:ql)?|mysql|mongodb)://([^:]+):([^@]+)@([^:/]+)(:\d+)?/([^\s'\"`]+)", curr)
                if db_match:
                    db_proto = db_match.group(1)
                    old_conn = db_match.group(0)
                    new_conn = f"{db_proto}://app_user:<REDACTED_PASSWORD>@198.51.100.10:5432/app_db"
                    curr = curr.replace(old_conn, new_conn)
                    changes.append(
                        RedactionChange(
                            line_number=line_idx,
                            original=old_conn,
                            redacted=new_conn,
                            reason="Database connection string credential sanitized",
                        )
                    )

            # 5. Redact Hyprland hardware descriptors
            if is_hyprland:
                desc_match = self._RE_HYPR_MONITOR_DESC.search(curr)
                if desc_match and not desc_match.group(2).startswith("<"):
                    orig_desc = desc_match.group(2)
                    curr = curr.replace(orig_desc, "<MONITOR_HARDWARE_DESCRIPTION>")
                    changes.append(
                        RedactionChange(
                            line_number=line_idx,
                            original=orig_desc,
                            redacted="<MONITOR_HARDWARE_DESCRIPTION>",
                            reason="Hardware monitor EDID / serial redacted",
                        )
                    )

            # 6. Scrub weather API keys and coordinates in Waybar custom scripts/configs
            if is_weather_context:
                curr = self._scrub_weather_line(curr, line_idx, changes)

            new_lines.append(curr)

        redacted_content = "".join(new_lines)
        return RedactionResult(
            file_path=filename,
            original_content=content,
            redacted_content=redacted_content,
            changes=changes,
            is_modified=bool(changes or redacted_content != content),
        )

    def redact_file(
        self,
        src_path: str | Path,
        dst_path: Optional[str | Path] = None,
        inplace: bool = False,
        template_suffix: Optional[str] = ".template",
    ) -> RedactionResult:
        """Sanitizes an existing file on disk and writes output or template."""
        src = Path(src_path)
        content = src.read_text(encoding="utf-8", errors="replace")
        result = self.redact_text(content, filename=str(src))

        if dst_path:
            out_target = Path(dst_path)
        elif inplace:
            out_target = src
        elif template_suffix:
            out_target = src.with_name(src.name + template_suffix)
        else:
            out_target = src

        out_target.parent.mkdir(parents=True, exist_ok=True)
        out_target.write_text(result.redacted_content, encoding="utf-8")

        return result
