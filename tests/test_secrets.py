"""Fail when a high-confidence secret pattern is committed."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", "site", "alerts", "lab"}
SKIP_FILES = {"docs/index.html", "docs/assets/attck-heatmap.svg"}
SUFFIXES = {".py", ".js", ".html", ".css", ".yml", ".yaml", ".json", ".md", ".txt", ".toml", ".cfg", ".ini", ".ps1", ".sh"}

PATTERNS = {
    "aws-access-key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github-pat": re.compile(r"ghp_[A-Za-z0-9]{36}"),
    "github-fine-grained-pat": re.compile(r"github_pat_[A-Za-z0-9_]{60,}"),
    "slack-token": re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "stripe-live-key": re.compile(r"sk_live_[0-9A-Za-z]{24,}"),
    "google-api-key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}


def test_no_high_confidence_secret_patterns() -> None:
    offenders: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.relative_to(ROOT).as_posix() in SKIP_FILES:
            continue
        if path.suffix.lower() not in SUFFIXES:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for name, pattern in PATTERNS.items():
            if pattern.search(text):
                offenders.append(f"{path.relative_to(ROOT).as_posix()} / {name}")

    assert not offenders, "High-confidence secret patterns found:\n" + "\n".join(offenders)
