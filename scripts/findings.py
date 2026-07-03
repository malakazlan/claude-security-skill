"""Core finding model shared by every scanner wrapper and pipeline stage."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # 0 = worst

# Common labels from tools -> normalized severity
_SEVERITY_MAP = {
    "critical": "critical",
    "blocker": "critical",
    "high": "high",
    "error": "high",
    "severe": "high",
    "medium": "medium",
    "moderate": "medium",
    "warning": "medium",
    "warn": "medium",
    "low": "low",
    "minor": "low",
    "note": "info",
    "info": "info",
    "informational": "info",
    "unknown": "medium",  # conservative: unknown is not "ignore"
    "": "medium",
}


def normalize_severity(raw: str | None) -> str:
    return _SEVERITY_MAP.get((raw or "").strip().lower(), "medium")


def _normalize_snippet(snippet: str) -> str:
    """Whitespace-insensitive normalization so fingerprints survive reformats."""
    return re.sub(r"\s+", " ", snippet or "").strip()


@dataclass
class Finding:
    tool: str
    rule_id: str
    severity: str          # critical/high/medium/low/info
    file: str              # repo-relative path
    line: int
    message: str
    snippet: str = ""      # code context; used for the stable fingerprint
    fix: str = ""          # optional remediation suggestion
    tags: list[str] = field(default_factory=list)
    # Triage annotations (set by the AI layer; deterministic path leaves defaults)
    suppressed: bool = False
    suppress_reason: str = ""
    triage_note: str = ""

    @property
    def fingerprint(self) -> str:
        """Stable ID for dedupe/baseline. Snippet-based so it survives line
        shifts; falls back to line number only when no snippet is available."""
        anchor = _normalize_snippet(self.snippet) or f"line:{self.line}"
        raw = "|".join([self.tool, self.rule_id, self.file, anchor])
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def dedupe_key(self) -> str:
        """Exact-duplicate guard: same tool, same rule, same file, same
        snippet => the identical finding reported twice. Distinct rules on the
        same line stay separate because rule_id is part of the key."""
        anchor = _normalize_snippet(self.snippet) or f"line:{self.line}"
        return hashlib.sha256(
            f"{self.tool}|{self.rule_id}|{self.file}|{anchor}".encode()
        ).hexdigest()[:16]

    @property
    def coalesce_key(self) -> str:
        """Cross-tool corroboration: different tools flagging the same file +
        snippet. Used to annotate agreement, not to drop distinct rules."""
        anchor = _normalize_snippet(self.snippet) or f"line:{self.line}"
        return hashlib.sha256(f"{self.file}|{anchor}".encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["fingerprint"] = self.fingerprint
        return d


def relpath(path: str | Path, repo: str | Path) -> str:
    try:
        return str(Path(path).resolve().relative_to(Path(repo).resolve()))
    except ValueError:
        return str(path)


def read_snippet(repo: Path, file: str, line: int, context: int = 0) -> str:
    """Read the flagged line (optionally +/- context) for fingerprinting and
    triage. Never raises."""
    try:
        p = (repo / file)
        if not p.is_file():
            return ""
        lines = p.read_text(errors="replace").splitlines()
        lo = max(0, line - 1 - context)
        hi = min(len(lines), line + context)
        return "\n".join(lines[lo:hi])[:2000]
    except Exception:
        return ""
