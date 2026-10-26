#!/usr/bin/env bash
# ==============================================================================
# Sanitize Guard: Zero-Leak & DevSecOps Security Gate
#
# Enforces:
# 1. Zero machine-specific filesystem paths in source code and documentation.
# 2. Zero OS username leaks across all repository files.
# 3. Zero local hostname leaks across all repository files.
# 4. Zero un-sanitized API tokens or active private credentials.
# 5. Strict Zero-Emoji compliance across all tracked files.
# 6. Privacy-preserving git committer/author configuration (noreply address).
# 7. 100% pass rate across automated test suite.
# 8. Clean self-audit of sanitize_guard package.
# ==============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "[security-audit] Starting Sanitize Guard zero-leak security gate..."

# 1. Determine list of tracked files
TRACKED_FILES="$(git ls-files 2>/dev/null || true)"
if [ -z "$TRACKED_FILES" ]; then
    echo "[security-audit] Notice: No git-tracked files yet; scanning working tree files."
    TRACKED_FILES="$(find sanitize_guard tests samples scripts pyproject.toml README.md -type f 2>/dev/null || true)"
fi

# 2. Check for machine-specific filesystem paths (/home/<user>, /Users/<user>, C:\Users\<user>)
echo "[security-audit] Checking for machine-specific path leaks..."
PATH_LEAKS="$(grep -rnE '(/home/[a-zA-Z0-9_-]+|/Users/[a-zA-Z0-9_-]+|C:\\\\Users\\\\[a-zA-Z0-9_-]+)' \
    sanitize_guard/ tests/ scripts/ pyproject.toml README.md 2>/dev/null | \
    grep -vE '(/home/<user>|/Users/<user>|C:\\Users\\<user>|/home/<username>|/home/username)' || true)"

if [ -n "$PATH_LEAKS" ]; then
    echo "[security-audit] FAIL: Machine-specific filesystem path leak detected:" >&2
    echo "$PATH_LEAKS" >&2
    exit 1
fi
echo "[security-audit] PASS: Zero machine-specific filesystem paths detected."

# 3. Check for current OS username leak
CURRENT_USER="$(whoami 2>/dev/null || echo "")"
if [ -n "$CURRENT_USER" ] && [ "$CURRENT_USER" != "root" ] && [ "$CURRENT_USER" != "runner" ]; then
    echo "[security-audit] Checking for local OS username leak ('$CURRENT_USER')..."
    USER_LEAKS="$(grep -rnF "$CURRENT_USER" sanitize_guard/ tests/ samples/ scripts/ pyproject.toml README.md assets/ 2>/dev/null | \
        grep -v "CURRENT_USER=" | grep -v "whoami" || true)"
    if [ -n "$USER_LEAKS" ]; then
        echo "[security-audit] FAIL: Local OS username leak detected in repository:" >&2
        echo "$USER_LEAKS" >&2
        exit 1
    fi
    echo "[security-audit] PASS: Zero OS username leaks detected."
fi

# 4. Check for local hostname leak
CURRENT_HOST="$(hostname 2>/dev/null || echo "")"
if [ -n "$CURRENT_HOST" ] && [ "$CURRENT_HOST" != "localhost" ] && [ "$CURRENT_HOST" != "localhost.localdomain" ] && [ "$CURRENT_HOST" != "$CURRENT_USER" ]; then
    echo "[security-audit] Checking for local hostname leak ('$CURRENT_HOST')..."
    HOST_LEAKS="$(grep -rnF "$CURRENT_HOST" sanitize_guard/ tests/ samples/ scripts/ pyproject.toml README.md 2>/dev/null | \
        grep -v "CURRENT_HOST=" | grep -v "hostname" || true)"
    if [ -n "$HOST_LEAKS" ]; then
        echo "[security-audit] FAIL: Local hostname leak detected in repository:" >&2
        echo "$HOST_LEAKS" >&2
        exit 1
    fi
    echo "[security-audit] PASS: Zero hostname leaks detected."
fi

# 5. Check for active credential patterns in production source code
echo "[security-audit] Checking for hardcoded credentials in production code..."
CRED_LEAKS="$(grep -rnE '(ghp_[A-Za-z0-9_]{36}|AKIA[0-9A-Z]{16}|sk-(?:live|test)_[A-Za-z0-9_]{20,})' sanitize_guard/ 2>/dev/null || true)"
if [ -n "$CRED_LEAKS" ]; then
    echo "[security-audit] FAIL: Active credential pattern detected in production code:" >&2
    echo "$CRED_LEAKS" >&2
    exit 1
fi
echo "[security-audit] PASS: Zero credentials in production code."

# 6. Check for emojis in all text files
echo "[security-audit] Checking for emoji characters in repository files..."
EMOJI_LEAK="$(python3 -c '
import os, sys

emoji_ranges = [
    (0x1F600, 0x1F64F), # Emoticons
    (0x1F300, 0x1F5FF), # Misc Symbols and Pictographs
    (0x1F680, 0x1F6FF), # Transport and Map
    (0x1F700, 0x1F77F), # Alchemical Symbols
    (0x1F780, 0x1F7FF), # Geometric Shapes Extended
    (0x1F800, 0x1F8FF), # Supplemental Arrows-C
    (0x1F900, 0x1F9FF), # Supplemental Symbols and Pictographs
    (0x1FA00, 0x1FA6F), # Chess Symbols
    (0x1FA70, 0x1FAFF), # Symbols and Pictographs Extended-A
    (0x2600, 0x26FF),   # Misc symbols
    (0x2700, 0x27BF),   # Dingbats
]

def has_emoji(text):
    for char in text:
        cp = ord(char)
        for start, end in emoji_ranges:
            if start <= cp <= end:
                return True, char
    return False, ""

leaks = []
for root, _, files in os.walk("."):
    if ".git" in root or "__pycache__" in root:
        continue
    for f in files:
        if f.endswith((".py", ".sh", ".md", ".toml", ".yml", ".yaml", ".conf", ".zshrc", ".gitconfig", ".env")):
            p = os.path.join(root, f)
            try:
                content = open(p, "r", encoding="utf-8", errors="ignore").read()
                found, ch = has_emoji(content)
                if found:
                    leaks.append(f"{p}: contains emoji U+{ord(ch):04X}")
            except Exception:
                pass

if leaks:
    print("\n".join(leaks))
    sys.exit(1)
sys.exit(0)
' 2>/dev/null || true)"

if [ -n "$EMOJI_LEAK" ]; then
    echo "[security-audit] FAIL: Emoji character detected in repository:" >&2
    echo "$EMOJI_LEAK" >&2
    exit 1
fi
echo "[security-audit] PASS: Zero emojis detected (strict compliance)."

# 7. Verify Git configuration
echo "[security-audit] Verifying git user identity configuration..."
GIT_EMAIL="$(git config user.email || echo "")"
if [[ "$GIT_EMAIL" != *"noreply.github.com"* ]]; then
    echo "[security-audit] FAIL: Git user.email ('$GIT_EMAIL') is not a sanitized noreply address." >&2
    exit 1
fi
echo "[security-audit] PASS: Git committer email is privacy-sanitized ($GIT_EMAIL)."

# 8. Run unit test suite
echo "[security-audit] Executing automated unit test suite..."
python3 -m unittest discover -s tests -v

# 9. Run Sanitize Guard self-audit on its own package
echo "[security-audit] Running Sanitize Guard self-audit on sanitize_guard/..."
python3 -m sanitize_guard.cli audit sanitize_guard/ --fail-on medium --format table

echo "[security-audit] ALL SECURITY & PRIVACY CHECKS PASSED SUCCESSFULLY."
exit 0
