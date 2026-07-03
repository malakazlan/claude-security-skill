#!/usr/bin/env python3
"""claude-security orchestrator.

Usage:
  scan.py <repo> [--target URL] [--spec PATH] [--fail-on LEVEL]
                 [--baseline findings.sarif] [--out DIR] [--no-triage]

Deterministic-first: runs applicable open-source scanners (the source of
truth), normalizes to SARIF, optionally triages with the AI layer, writes a
report + SARIF, and returns a CI-gating exit code.
"""

from __future__ import annotations

import argparse
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))

from findings import SEVERITY_RANK, SEVERITIES  # noqa: E402
from detect import detect  # noqa: E402
from config import load_config  # noqa: E402
from normalize import (dedupe, load_baseline, apply_suppressions,  # noqa: E402
                       apply_ignore_paths, write_sarif)
from report import write_report  # noqa: E402
from scanners import CORE_SCANNERS, SchemathesisScanner, ZapBaselineScanner  # noqa: E402
import triage as triage_mod  # noqa: E402


def parse_args(argv=None):
    ap = argparse.ArgumentParser(prog="claude-security")
    ap.add_argument("repo", help="path to the repository to scan")
    ap.add_argument("--target", default="",
                    help="URL of a RUNNING app you own — enables opt-in DAST")
    ap.add_argument("--spec", default="",
                    help="path/URL to an OpenAPI spec for API fuzzing (DAST)")
    ap.add_argument("--fail-on", default="",
                    choices=["critical", "high", "medium", "low", "info"],
                    help="gate threshold (default from config or 'high')")
    ap.add_argument("--baseline", default="",
                    help="baseline SARIF; only NEW findings count toward the gate")
    ap.add_argument("--out", default=".",
                    help="output directory for report + sarif (default: cwd)")
    ap.add_argument("--no-triage", action="store_true",
                    help="force-skip the AI triage layer")
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    repo = Path(args.repo).resolve()
    if not repo.is_dir():
        print(f"error: {repo} is not a directory", file=sys.stderr)
        return 2

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    config = load_config(repo)
    if args.no_triage:
        config.setdefault("triage", {})["enabled"] = False
    fail_on = args.fail_on or config.get("fail_on", "high")

    print(f"[*] scanning {repo}")
    profile = detect(repo)
    print(f"[*] {profile.summary()}")

    # ---- assemble applicable scanners ---------------------------------
    instances = [cls(config) for cls in CORE_SCANNERS]
    if args.target:
        print(f"[!] DAST enabled against {args.target} — "
              "you MUST own or be authorized to test this target.")
        instances.append(SchemathesisScanner(config, target=args.target, spec=args.spec))
        instances.append(ZapBaselineScanner(config, target=args.target))

    # ---- run in parallel, never crash on one tool ---------------------
    results = []
    with ThreadPoolExecutor(max_workers=min(8, len(instances) or 1)) as ex:
        futs = {ex.submit(s.run, repo, profile): s for s in instances}
        for fut in as_completed(futs):
            res = fut.result()
            results.append(res)
            icon = {"ran": "✓", "skipped_missing": "○",
                    "skipped_not_applicable": "·", "timeout": "⏱",
                    "error": "✗"}.get(res.status, "?")
            print(f"  {icon} {res.scanner}: {res.status} — {res.detail}")

    all_findings = [f for r in results for f in r.findings]
    print(f"[*] {len(all_findings)} raw finding(s) before dedupe")

    # ---- normalize: ignore_paths, dedupe, baseline, suppressions ------
    before = len(all_findings)
    all_findings = apply_ignore_paths(all_findings,
                                      config.get("ignore_paths", []))
    if before != len(all_findings):
        print(f"[*] {before - len(all_findings)} finding(s) dropped "
              "via ignore_paths")
    all_findings = dedupe(all_findings)
    apply_suppressions(all_findings, config.get("suppressions", []))
    baseline = load_baseline(args.baseline)
    if baseline:
        print(f"[*] baseline loaded: {len(baseline)} known fingerprint(s)")

    # ---- AI triage (optional) -----------------------------------------
    all_findings, semantic, triage_msg = triage_mod.run_triage(
        all_findings, repo, profile, config)
    semantic = apply_ignore_paths(semantic, config.get("ignore_paths", []))
    print(f"[*] {triage_msg}")

    # ---- write outputs -------------------------------------------------
    sarif_path = out_dir / "findings.sarif"
    write_sarif(all_findings + semantic, sarif_path, baseline)

    gate_passed, gate_findings = evaluate_gate(
        all_findings, fail_on, baseline)

    report_path = out_dir / "security-report.md"
    write_report(report_path, all_findings, semantic, results, profile,
                 fail_on, gate_passed, triage_msg, target=args.target)

    print(f"[*] wrote {report_path}")
    print(f"[*] wrote {sarif_path}")

    if gate_passed:
        print(f"[✓] gate PASS — no unsuppressed findings at/above '{fail_on}'"
              + (" (new vs baseline)" if baseline else ""))
        return 0
    print(f"[✗] gate FAIL — {len(gate_findings)} finding(s) at/above '{fail_on}'"
          + (" (new vs baseline)" if baseline else ""))
    return 1


def evaluate_gate(findings, fail_on, baseline):
    """Gate fails on unsuppressed, non-semantic findings at/above threshold
    that are NOT in the baseline. Semantic findings never gate (they need
    human confirmation)."""
    threshold = SEVERITY_RANK[fail_on]
    gating = [
        f for f in findings
        if not f.suppressed
        and "ai-semantic" not in f.tags
        and SEVERITY_RANK[f.severity] <= threshold
        and f.fingerprint not in baseline
    ]
    return (len(gating) == 0), gating


if __name__ == "__main__":
    sys.exit(main())
