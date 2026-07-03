"""Secrets wrappers: gitleaks, trufflehog.

IMPORTANT: secret *values* are redacted at ingestion. They never enter the
SARIF, the report, or any AI triage request.
"""

from __future__ import annotations

import json
from pathlib import Path

from .base import Scanner
from findings import Finding, read_snippet, relpath


def _redact(value: str) -> str:
    if not value:
        return "[REDACTED]"
    v = str(value)
    return f"[REDACTED:{len(v)} chars, starts '{v[:3]}…']" if len(v) > 6 else "[REDACTED]"


class GitleaksScanner(Scanner):
    name = "gitleaks"
    binary = "gitleaks"
    category = "secrets"

    def command(self, repo: Path) -> list[str]:
        mode = [] if (repo / ".git").exists() else ["--no-git"]
        return [self.binary, "detect", "--source", str(repo),
                "--report-format", "json", "--report-path", "/dev/stdout",
                "--no-banner", "--exit-code", "0", *mode]

    def parse(self, stdout, stderr, returncode, repo):
        out = []
        data = json.loads(stdout or "[]")
        for r in data:
            file = r.get("File", "")
            line = int(r.get("StartLine", 1) or 1)
            out.append(Finding(
                tool=self.name,
                rule_id=r.get("RuleID", "gitleaks.rule"),
                severity="critical",  # a leaked credential is always critical until rotated
                file=file, line=line,
                message=(f"Potential secret ({r.get('Description', 'secret')}) "
                         f"detected: {_redact(r.get('Secret', ''))}")[:500],
                snippet=f"{r.get('RuleID')}@{file}:{line}",  # NOT the secret
                fix="Rotate the credential immediately, purge it from git "
                    "history (git filter-repo), and move it to a secret manager.",
                tags=["secrets"],
            ))
        return out


class TrufflehogScanner(Scanner):
    name = "trufflehog"
    binary = "trufflehog"
    category = "secrets"
    timeout = 600  # git-history scans on large repos can be slow

    def command(self, repo: Path) -> list[str]:
        return [self.binary, "filesystem", str(repo), "--json", "--no-update"]

    def parse(self, stdout, stderr, returncode, repo):
        out, seen = [], set()
        for ln in (stdout or "").splitlines():
            ln = ln.strip()
            if not ln.startswith("{"):
                continue
            try:
                r = json.loads(ln)
            except json.JSONDecodeError:
                continue
            meta = (r.get("SourceMetadata", {}).get("Data", {})
                     .get("Filesystem", {}))
            file = relpath(meta.get("file", ""), repo)
            line = int(meta.get("line", 1) or 1)
            det = r.get("DetectorName", "trufflehog.rule")
            key = (det, file, line)
            if key in seen:
                continue
            seen.add(key)
            verified = bool(r.get("Verified"))
            out.append(Finding(
                tool=self.name,
                rule_id=det,
                severity="critical" if verified else "high",
                file=file, line=line,
                message=(f"{'VERIFIED live' if verified else 'Potential'} "
                         f"{det} credential: "
                         f"{_redact(r.get('Raw', ''))}")[:500],
                snippet=f"{det}@{file}:{line}",  # NOT the secret
                fix="Rotate the credential immediately and move it to a "
                    "secret manager.",
                tags=["secrets"] + (["verified"] if verified else []),
            ))
        return out
