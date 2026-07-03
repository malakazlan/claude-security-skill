"""Normalize findings to SARIF 2.1.0, dedupe, and apply baseline/suppressions."""

from __future__ import annotations

import json
from pathlib import Path

from findings import Finding, SEVERITY_RANK, SEVERITIES

SARIF_LEVEL = {  # SARIF only has error/warning/note
    "critical": "error", "high": "error",
    "medium": "warning", "low": "warning", "info": "note",
}


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Two-stage dedupe.

    1. Drop exact duplicates (same tool+rule+file+snippet).
    2. Across the survivors, when *different tools* flag the same file+snippet,
       annotate the highest-severity one with which other tools corroborated it
       — but keep distinct rules separate (two different rules on one line are
       two real findings, not a duplicate).
    """
    # Stage 1: exact duplicates
    exact: dict[str, Finding] = {}
    for f in findings:
        exact.setdefault(f.dedupe_key, f)
    survivors = list(exact.values())

    # Stage 2: cross-tool corroboration annotation
    groups: dict[str, list[Finding]] = {}
    for f in survivors:
        groups.setdefault(f.coalesce_key, []).append(f)

    for group in groups.values():
        tools = {f.tool for f in group}
        if len(tools) > 1:
            for f in group:
                others = sorted(t for t in tools if t != f.tool)
                for o in others:
                    tag = f"also:{o}"
                    if tag not in f.tags:
                        f.tags.append(tag)
    return survivors


def load_baseline(path: str | Path | None) -> set[str]:
    """Return the set of fingerprints already present in a baseline SARIF."""
    if not path:
        return set()
    p = Path(path)
    if not p.is_file():
        return set()
    data = json.loads(p.read_text())
    fps = set()
    for run in data.get("runs", []):
        for res in run.get("results", []):
            fp = (res.get("partialFingerprints", {}) or {}).get("csFingerprint")
            if fp:
                fps.add(fp)
    return fps


def apply_suppressions(findings: list[Finding], suppressions: list[dict]) -> None:
    """Mark findings whose fingerprint appears in the config suppressions list.
    Each suppression must carry a justification (enforced in config load)."""
    by_fp = {s.get("fingerprint"): s for s in (suppressions or [])}
    for f in findings:
        s = by_fp.get(f.fingerprint)
        if s:
            f.suppressed = True
            f.suppress_reason = s.get("justification", "suppressed via config")


def to_sarif(findings: list[Finding], baseline: set[str] | None = None) -> dict:
    baseline = baseline or set()
    rules_by_tool: dict[str, dict] = {}
    results = []

    for f in findings:
        rules_by_tool.setdefault(f.tool, {})
        rules_by_tool[f.tool].setdefault(f.rule_id, {
            "id": f.rule_id,
            "shortDescription": {"text": f.rule_id},
            "properties": {"category": next((t for t in f.tags), "")},
        })
        suppressed = f.suppressed or (f.fingerprint in baseline)
        result = {
            "ruleId": f.rule_id,
            "level": SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": max(1, f.line)},
                }
            }],
            "partialFingerprints": {"csFingerprint": f.fingerprint},
            "properties": {
                "tool": f.tool,
                "severity": f.severity,
                "tags": f.tags,
                "fix": f.fix,
                "triageNote": f.triage_note,
                "inBaseline": f.fingerprint in baseline,
            },
        }
        if suppressed:
            result["suppressions"] = [{
                "kind": "external" if f.fingerprint in baseline else "inSource",
                "justification": (f.suppress_reason or
                                  ("present in baseline" if f.fingerprint in baseline
                                   else "suppressed")),
            }]
        results.append(result)

    # one "run" per originating tool keeps GitHub code-scanning tidy
    runs = []
    for tool, rules in rules_by_tool.items():
        tool_results = [r for r in results if r["properties"]["tool"] == tool]
        runs.append({
            "tool": {"driver": {
                "name": f"claude-security/{tool}",
                "informationUri": "https://github.com/your-org/claude-security",
                "rules": list(rules.values()),
            }},
            "results": tool_results,
        })

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs or [{
            "tool": {"driver": {"name": "claude-security", "rules": []}},
            "results": [],
        }],
    }


def write_sarif(findings: list[Finding], out_path: str | Path,
                baseline: set[str] | None = None) -> None:
    Path(out_path).write_text(json.dumps(to_sarif(findings, baseline), indent=2))
