"""Render the human-readable security-report.md from findings + scan metadata."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from findings import Finding, SEVERITIES, SEVERITY_RANK

_SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡",
              "low": "🔵", "info": "⚪"}


def _counts(findings):
    c = {s: 0 for s in SEVERITIES}
    for f in findings:
        if not f.suppressed:
            c[f.severity] += 1
    return c


def build_report(findings, semantic, scan_results, profile,
                 fail_on, gate_passed, triage_msg, target=None) -> str:
    active = [f for f in findings if not f.suppressed]
    suppressed = [f for f in findings if f.suppressed]
    counts = _counts(findings)
    total = sum(counts.values())
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    L = []
    L.append("# Security Audit Report")
    L.append("")
    L.append(f"_Generated {now} by **claude-security**_")
    L.append("")

    # ---- executive summary --------------------------------------------
    L.append("## Executive summary")
    L.append("")
    gate = "✅ PASS" if gate_passed else "❌ FAIL"
    L.append(f"**CI gate ({fail_on}+):** {gate}")
    L.append("")
    L.append("| Severity | Count |")
    L.append("|----------|-------|")
    for s in SEVERITIES:
        L.append(f"| {_SEV_EMOJI[s]} {s.capitalize()} | {counts[s]} |")
    L.append(f"| **Total (unsuppressed)** | **{total}** |")
    if suppressed:
        L.append(f"| _Suppressed_ | _{len(suppressed)}_ |")
    L.append("")

    # ---- coverage / limits --------------------------------------------
    L.append("## Coverage & limitations")
    L.append("")
    L.append(f"Repo profile: {profile.summary()}")
    L.append("")
    ran = [r for r in scan_results if r.status == "ran"]
    skipped = [r for r in scan_results if r.status != "ran"]
    L.append("**Scanners that ran:**")
    if ran:
        for r in ran:
            L.append(f"- `{r.scanner}` — {r.detail}")
    else:
        L.append("- _none_")
    L.append("")
    L.append("**Scanners skipped / failed:**")
    if skipped:
        for r in skipped:
            L.append(f"- `{r.scanner}` — {r.status}: {r.detail}")
    else:
        L.append("- _none_")
    L.append("")
    if triage_msg:
        L.append(f"**AI triage:** {triage_msg}")
        L.append("")
    L.append("> ⚠️ **This is not a security guarantee.** A clean result means "
             "the configured scanners found nothing at or above the threshold — "
             "not that the code is free of vulnerabilities. Coverage is limited "
             "to the tools that ran and the files they understood. Dynamic "
             "behavior, novel logic flaws, and anything outside scanned paths "
             "may be missed. Treat this as one input to a review process, not a "
             "sign-off.")
    L.append("")

    # ---- findings by severity -----------------------------------------
    L.append("## Findings")
    L.append("")
    non_semantic = [f for f in active if "ai-semantic" not in f.tags]
    if not non_semantic:
        L.append("_No unsuppressed findings from deterministic scanners._")
        L.append("")
    else:
        by_sev = sorted(non_semantic, key=lambda f: (SEVERITY_RANK[f.severity], f.file))
        cur = None
        for f in by_sev:
            if f.severity != cur:
                cur = f.severity
                L.append(f"### {_SEV_EMOJI[cur]} {cur.capitalize()}")
                L.append("")
            L.extend(_render_finding(f))

    # ---- ai-semantic section ------------------------------------------
    sem_active = [f for f in semantic if not f.suppressed]
    L.append("## 🧠 Needs human review — AI semantic findings")
    L.append("")
    L.append("_These are reasoned over code by the AI layer to catch classes "
             "static scanners structurally miss (broken authorization, "
             "business-logic flaws, config gaps). They are **candidates** and "
             "require human confirmation — they are not confirmed vulnerabilities "
             "and are excluded from the CI gate count._")
    L.append("")
    if not sem_active:
        L.append("_None surfaced (or AI triage was skipped)._")
        L.append("")
    else:
        for f in sorted(sem_active, key=lambda f: SEVERITY_RANK[f.severity]):
            L.extend(_render_finding(f, semantic=True))

    # ---- suppressed ----------------------------------------------------
    if suppressed:
        L.append("## Suppressed findings")
        L.append("")
        for f in suppressed:
            L.append(f"- `{f.severity}` **{f.rule_id}** {f.file}:{f.line} — "
                     f"{f.suppress_reason}")
        L.append("")

    L.append("---")
    L.append("_Deterministic-first: scanners are the source of truth; the AI "
             "layer only triages, ranks, and reasons about semantic gaps on top "
             "of real code. It never invents deterministic findings._")
    return "\n".join(L) + "\n"


def _render_finding(f: Finding, semantic=False):
    out = []
    tools = f.tool + "".join(f" (+{t.split(':',1)[1]})"
                             for t in f.tags if t.startswith("also:"))
    out.append(f"**{f.rule_id}** — `{f.file}:{f.line}`  ")
    out.append(f"_{tools}_")
    out.append("")
    out.append(f"{f.message}")
    out.append("")
    if f.snippet and semantic:
        snippet = f.snippet.strip()
        if snippet:
            out.append("```")
            out.append(snippet[:600])
            out.append("```")
    if f.fix:
        out.append(f"**Fix:** {f.fix}")
        out.append("")
    if f.triage_note:
        out.append(f"_Triage: {f.triage_note}_")
        out.append("")
    out.append("")
    return out


def write_report(path, *args, **kwargs):
    Path(path).write_text(build_report(*args, **kwargs))
