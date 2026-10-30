"""Command-line interface for Sanitize Guard.

Subcommands:
- audit / scan: Scan directory or files for PII, paths, credentials, and media metadata.
- scrub-media: Strip metadata chunks from PNG, JPEG, GIF, WebP, MP3, and WAV media.
- redact-dotfiles: Transform personal dotfiles into safe public templates.
- check-git: Forensic audit of git commit graph authors, emails, and patches.
- install-hook: Install automated pre-commit or pre-push zero-leak security gates.
"""

from __future__ import annotations

import argparse
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Optional, Sequence

from sanitize_guard.dotfile_redactor import DotfileRedactor
from sanitize_guard.media_scrubber import (
    SUPPORTED_EXTENSIONS,
    MediaScrubber,
)
from sanitize_guard.pii_engine import (
    PIIEngine,
    PIIFinding,
    RuleID,
    SanitizeIgnore,
    Severity,
)
from sanitize_guard.sarif import ASCIITableExporter, SARIFExporter

SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
    Severity.INFO: 0,
}

FAIL_ON_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "none": None,
}


def cmd_audit(args: argparse.Namespace) -> int:
    """Executes the 'audit' or 'scan' subcommand."""
    target_path = Path(args.path).resolve()
    if not target_path.exists():
        print(f"Error: Target path '{args.path}' does not exist.", file=sys.stderr)
        return 2

    # Load .sanitizeignore from target directory or repository root
    ignore_dir = target_path if target_path.is_dir() else target_path.parent
    sanitize_ignore = SanitizeIgnore.load(ignore_dir)

    # Parse ignore patterns
    ignore_patterns = [p.strip() for p in args.ignore.split(",") if p.strip()] if args.ignore else None

    # Initialize PII engine
    target_users = [args.target_user] if args.target_user else None
    target_hosts = [args.target_host] if args.target_host else None
    engine = PIIEngine(
        target_usernames=target_users,
        target_hostnames=target_hosts,
        auto_detect_system=not args.no_auto_detect,
        sanitize_ignore=sanitize_ignore,
    )

    findings: list[PIIFinding] = []

    # Scan text files
    if target_path.is_file():
        findings.extend(engine.scan_file(target_path))
    else:
        findings.extend(engine.scan_directory(target_path, ignore_patterns=ignore_patterns))

    # Also inspect supported media files (images and audio) if present
    media_files: list[Path] = []
    if target_path.is_file():
        if target_path.suffix.lower() in SUPPORTED_EXTENSIONS:
            if not sanitize_ignore.is_file_ignored(target_path):
                media_files.append(target_path)
    else:
        for root, _, files in os.walk(target_path):
            if ".git" in root or "__pycache__" in root:
                continue
            for f in files:
                p = Path(root) / f
                if p.suffix.lower() in SUPPORTED_EXTENSIONS:
                    if not sanitize_ignore.is_file_ignored(p):
                        media_files.append(p)

    for media_p in media_files:
        try:
            _, chunk_findings = MediaScrubber.inspect_file(media_p)
            for cf in chunk_findings:
                rel_p = str(media_p.relative_to(target_path)) if target_path.is_dir() else str(media_p)
                findings.append(
                    PIIFinding(
                        rule_id=RuleID("SAN-010"),
                        severity=Severity.MEDIUM,
                        description=cf.description,
                        file_path=rel_p,
                        line_number=1,
                        column=1,
                        matched_text=cf.chunk_type,
                        replacement=None,
                        is_leak=True,
                    )
                )
        except Exception:
            pass

    # Format output
    out_format = args.format.lower()
    if out_format == "sarif":
        report_text = SARIFExporter.to_json(findings)
    elif out_format == "json":
        import json
        report_text = json.dumps([f.to_dict() for f in findings], indent=2)
    else:
        table_exporter = ASCIITableExporter(no_color=args.no_color)
        report_text = table_exporter.format_table(findings)

    if args.output:
        out_p = Path(args.output)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(report_text, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(report_text)

    # Check failure threshold
    threshold = FAIL_ON_MAP.get(args.fail_on.lower())
    if threshold is not None:
        thresh_val = SEVERITY_ORDER[threshold]
        has_failure = any(
            f.is_leak and SEVERITY_ORDER[f.severity] >= thresh_val
            for f in findings
        )
        if has_failure:
            return 1

    return 0


def cmd_scrub_media(args: argparse.Namespace) -> int:
    """Executes the 'scrub-media' subcommand."""
    targets: list[Path] = []
    for p_str in args.paths:
        p = Path(p_str)
        if p.is_file():
            targets.append(p)
        elif p.is_dir():
            for root, _, files in os.walk(p):
                for f in files:
                    ext = Path(f).suffix.lower()
                    if ext in SUPPORTED_EXTENSIONS:
                        targets.append(Path(root) / f)

    if not targets:
        ext_list = ", ".join(sorted(SUPPORTED_EXTENSIONS))
        print(f"No media files ({ext_list}) found to scrub.")
        return 0

    total_saved = 0
    total_stripped = 0
    modified_count = 0

    print(f"Found {len(targets)} media file(s). Processing...")

    for media_p in targets:
        try:
            raw_data = media_p.read_bytes()
            fmt, findings = MediaScrubber.inspect_bytes(raw_data)
            if not findings:
                if args.verbose:
                    print(f"  [CLEAN] {media_p} (0 metadata chunks)")
                continue

            stripped_names = [f.chunk_type for f in findings]
            if args.dry_run:
                print(f"  [DRY-RUN] {media_p}: would strip {len(findings)} chunk(s): {', '.join(stripped_names)}")
                continue

            out_target = None
            if args.output:
                out_dir = Path(args.output)
                out_target = out_dir / media_p.name

            res = MediaScrubber.scrub_file(
                src_path=media_p,
                dst_path=out_target,
                inplace=args.inplace or (not args.output),
            )

            if res.error:
                print(f"  [ERROR] {media_p}: {res.error}", file=sys.stderr)
            elif res.is_modified:
                modified_count += 1
                total_saved += res.bytes_saved
                total_stripped += len(res.stripped_chunks)
                print(
                    f"  [SCRUBBED] {media_p} ({res.media_format}): "
                    f"removed {len(res.stripped_chunks)} chunk(s) [{', '.join(res.stripped_chunks)}], "
                    f"saved {res.bytes_saved} bytes"
                )
        except Exception as e:
            print(f"  [SKIP] {media_p}: {e}", file=sys.stderr)

    print("-" * 60)
    print(
        f"Media Scrubbing Summary: {modified_count}/{len(targets)} files scrubbed | "
        f"{total_stripped} chunks stripped | {total_saved} bytes eliminated"
    )
    return 0


def cmd_redact_dotfiles(args: argparse.Namespace) -> int:
    """Executes the 'redact-dotfiles' subcommand."""
    redactor = DotfileRedactor(
        default_git_name=args.git_name,
        default_git_email=args.git_email,
    )

    targets: list[Path] = []
    for p_str in args.files:
        p = Path(p_str)
        if p.is_file():
            targets.append(p)
        elif p.is_dir():
            for root, _, files in os.walk(p):
                for f in files:
                    targets.append(Path(root) / f)

    if not targets:
        print("No files specified for dotfile redaction.")
        return 0

    total_changes = 0
    modified_files = 0

    for file_p in targets:
        try:
            content = file_p.read_text(encoding="utf-8", errors="replace")
            res = redactor.redact_text(content, filename=str(file_p))

            if not res.is_modified:
                if args.verbose:
                    print(f"  [NO CHANGES] {file_p}")
                continue

            modified_files += 1
            total_changes += len(res.changes)

            if args.output:
                out_p = Path(args.output) / file_p.name
            elif args.inplace:
                out_p = file_p
            else:
                out_p = file_p.with_name(file_p.name + args.suffix)

            out_p.parent.mkdir(parents=True, exist_ok=True)
            out_p.write_text(res.redacted_content, encoding="utf-8")

            print(f"  [REDACTED] {file_p} -> {out_p} ({len(res.changes)} replacements)")
            if args.verbose:
                for c in res.changes:
                    print(f"    Line {c.line_number}: {c.reason} ('{c.original[:30]}' -> '{c.redacted[:30]}')")

        except Exception as e:
            print(f"  [ERROR] {file_p}: {e}", file=sys.stderr)

    print("-" * 60)
    print(f"Dotfile Redaction Summary: {modified_files}/{len(targets)} files modified | {total_changes} redactions applied")
    return 0


def cmd_check_git(args: argparse.Namespace) -> int:
    """Executes forensic check on git commit history."""
    try:
        rev_parse = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            check=False,
        )
        if rev_parse.returncode != 0:
            print("Error: Not inside a git repository.", file=sys.stderr)
            return 2

        log_format = "%H|%an|%ae|%s"
        max_commits = args.commits if args.commits > 0 else 100
        cmd = ["git", "log", f"-n{max_commits}", f"--format={log_format}"]
        if args.branch:
            cmd.append(args.branch)

        res = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if res.returncode != 0 or not res.stdout.strip():
            print("Notice: No commits found in repository branch.")
            return 0

        engine = PIIEngine()
        leaks_found: list[str] = []

        for line in res.stdout.strip().splitlines():
            parts = line.split("|", 3)
            if len(parts) < 4:
                continue

            commit_hash, author_name, author_email, subject = parts
            short_hash = commit_hash[:8]

            # 1. Verify author email is noreply
            if "noreply" not in author_email.lower():
                leaks_found.append(
                    f"[{short_hash}] Commit email '{author_email}' is not a privacy-sanitized noreply address"
                )

            # 2. Check commit message for PII
            msg_findings = engine.scan_text(subject, file_path=f"commit:{short_hash}")
            for f in msg_findings:
                if f.is_leak:
                    leaks_found.append(
                        f"[{short_hash}] Commit subject leaks {f.rule_id.value} ({f.description}): '{f.matched_text}'"
                    )

            # 3. Check commit patch diff
            diff_res = subprocess.run(
                ["git", "diff-tree", "-p", "-r", "--no-commit-id", commit_hash],
                capture_output=True,
                text=True,
                check=False,
            )
            if diff_res.returncode == 0:
                current_file = ""
                added_lines: list[str] = []
                for d_line in diff_res.stdout.splitlines():
                    if d_line.startswith("diff --git a/"):
                        parts = d_line.split()
                        if len(parts) >= 4:
                            current_file = parts[3].lstrip("b/")
                    elif d_line.startswith("+++ b/"):
                        current_file = d_line[6:]
                    elif d_line.startswith("+") and not d_line.startswith("+++"):
                        if not any(current_file.startswith(pfx) for pfx in ("tests/", "samples/", "fixtures/")):
                            added_lines.append(d_line[1:])

                if added_lines:
                    diff_text = "\n".join(added_lines)
                    diff_findings = engine.scan_text(diff_text, file_path=f"diff:{short_hash}")
                    for df in diff_findings:
                        if df.is_leak and df.severity in (Severity.CRITICAL, Severity.HIGH):
                            leaks_found.append(
                                f"[{short_hash}] Patch diff introduced {df.rule_id.value} ({df.description}): '{df.matched_text}'"
                            )

        if leaks_found:
            print("[FAIL] Git commit-graph forensic audit detected leaks:")
            for leak in leaks_found:
                print(f"  * {leak}")
            if args.fail_on_leak:
                return 1
        else:
            print("[PASS] Git commit-graph forensic audit: Zero personal emails, paths, or secrets detected.")

        return 0
    except Exception as e:
        print(f"Error checking git repository: {e}", file=sys.stderr)
        return 1


def cmd_install_hook(args: argparse.Namespace) -> int:
    """Installs zero-leak git hook (defaults to pre-commit)."""
    repo_path = Path(args.path).resolve()
    git_dir = repo_path / ".git"
    if not git_dir.is_dir():
        print(f"Error: No .git directory found at '{repo_path}'.", file=sys.stderr)
        return 2

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)

    hook_name = getattr(args, "hook", "pre-commit") or "pre-commit"
    hook_name = hook_name.lower()
    hook_file = hooks_dir / hook_name

    script_content = f"""#!/usr/bin/env bash
# ==============================================================================
# Sanitize Guard: Automated {hook_name} Zero-Leak Gate
# Blocks commits or pushes containing un-sanitized paths, OS users, or credentials.
# ==============================================================================
set -euo pipefail

echo "[sanitize-guard] Executing {hook_name} zero-leak audit..."

# Resolve executable command
if command -v sanitize-guard >/dev/null 2>&1; then
    RUNNER="sanitize-guard"
elif command -v sanitize >/dev/null 2>&1; then
    RUNNER="sanitize"
else
    RUNNER="python3 -m sanitize_guard.cli"
fi

# 1. Audit working tree files for unredacted PII and unstripped media metadata
$RUNNER scan . --fail-on medium --format table

# 2. Check git commit-graph integrity
$RUNNER check-git --fail-on-leak

echo "[sanitize-guard] PASS: Repository is clean and sanitized. Commit authorized."
exit 0
"""

    hook_file.write_text(script_content, encoding="utf-8")
    # Make executable
    hook_file.chmod(hook_file.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    print(f"Successfully installed zero-leak hook: {hook_file}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Builds top-level CLI argument parser with subcommands."""
    parser = argparse.ArgumentParser(
        prog="sanitize",
        description="Sanitize Guard: Zero-dependency DevSecOps & Privacy Engineering Toolkit",
    )
    subparsers = parser.add_subparsers(dest="subcommand", help="Available subcommands")

    # Subcommands: audit and scan (aliases)
    for sub_name in ("audit", "scan"):
        p_sub = subparsers.add_parser(sub_name, help="Scan directory or files for PII and metadata leaks")
        p_sub.add_argument("path", nargs="?", default=".", help="Path to directory or file (default: .)")
        p_sub.add_argument("--format", choices=["table", "sarif", "json"], default="table", help="Output report format")
        p_sub.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"], default="high", help="Failure threshold")
        p_sub.add_argument("--ignore", default="", help="Comma-separated ignore patterns")
        p_sub.add_argument("--output", "-o", default="", help="Output report file path")
        p_sub.add_argument("--target-user", default="", help="Specific OS username to scan for")
        p_sub.add_argument("--target-host", default="", help="Specific hostname to scan for")
        p_sub.add_argument("--no-auto-detect", action="store_true", help="Disable automatic detection of system user/host")
        p_sub.add_argument("--no-color", action="store_true", help="Disable ANSI color output")

    # Subcommand: scrub-media
    p_scrub = subparsers.add_parser("scrub-media", help="Strip metadata chunks from PNG, JPEG, GIF, WebP, MP3, and WAV media")
    p_scrub.add_argument("paths", nargs="+", help="Files or directories to scrub")
    p_scrub.add_argument("--inplace", action="store_true", help="Overwrite input images directly")
    p_scrub.add_argument("--output", "-o", default="", help="Directory to save cleaned images")
    p_scrub.add_argument("--dry-run", action="store_true", help="Simulate without modifying files")
    p_scrub.add_argument("--verbose", "-v", action="store_true", help="Show verbose output")

    # Subcommand: redact-dotfiles
    p_redact = subparsers.add_parser("redact-dotfiles", help="Transform personal dotfiles into safe public templates")
    p_redact.add_argument("files", nargs="+", help="Dotfile(s) or directories to redact")
    p_redact.add_argument("--inplace", action="store_true", help="Overwrite dotfiles directly")
    p_redact.add_argument("--suffix", default=".template", help="Suffix for template output (default: .template)")
    p_redact.add_argument("--output", "-o", default="", help="Directory to save templates")
    p_redact.add_argument("--git-name", default="1MEshh", help="Public replacement git user name")
    p_redact.add_argument("--git-email", default="152591660+1MEshh@users.noreply.github.com", help="Public replacement git email")
    p_redact.add_argument("--verbose", "-v", action="store_true", help="Show replacement details")

    # Subcommand: check-git
    p_check_git = subparsers.add_parser("check-git", help="Audit git commits for author emails and patch leaks")
    p_check_git.add_argument("--commits", type=int, default=50, help="Number of recent commits to inspect")
    p_check_git.add_argument("--branch", default="", help="Git branch to check (default: HEAD)")
    p_check_git.add_argument("--fail-on-leak", action="store_true", help="Exit with code 1 if any leak is detected")

    # Subcommand: install-hook
    p_hook = subparsers.add_parser("install-hook", help="Install automated zero-leak git hook (default: pre-commit)")
    p_hook.add_argument("--hook", choices=["pre-commit", "pre-push"], default="pre-commit", help="Hook type (default: pre-commit)")
    p_hook.add_argument("--path", default=".", help="Repository root path")

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Main CLI entrypoint."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.subcommand:
        parser.print_help()
        return 0

    if args.subcommand in ("audit", "scan"):
        return cmd_audit(args)
    elif args.subcommand == "scrub-media":
        return cmd_scrub_media(args)
    elif args.subcommand == "redact-dotfiles":
        return cmd_redact_dotfiles(args)
    elif args.subcommand == "check-git":
        return cmd_check_git(args)
    elif args.subcommand == "install-hook":
        return cmd_install_hook(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
