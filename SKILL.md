---
name: claude-security
description: Use this skill to run a full security audit on a code repository. Runs SAST, dependency, secret, IaC, and optional API/DAST scanners, normalizes results to SARIF, uses AI to filter false positives and catch authorization/business-logic flaws scanners miss, and outputs a report plus a CI-gating exit code. Trigger when the user wants to security-scan, audit, or find vulnerabilities in a codebase — including phrasings like "is this code safe", "check for secrets/CVEs", "pentest this", "security review before deploy", "any vulnerabilities here", "OWASP check", or "audit my dependencies", even if they don't say the word "security".
---

# claude-security

A security audit **orchestrator**. It points battle-tested open-source
scanners at a repository, normalizes their output to SARIF, then (optionally)
uses an AI triage layer to remove false positives, re-rank by real risk, and
catch vulnerability classes scanners structurally miss (broken authorization,
business-logic flaws, insecure config). It emits one markdown report, a
machine-readable SARIF file, and a pass/fail exit code for CI gating.

## Core philosophy: deterministic-first

The scanners are the source of truth. The AI layer **never invents**
deterministic findings — it only triages, ranks, explains, and reasons about
semantic gaps on top of real code. A clean result is **not** a security
guarantee; it means the configured tools found nothing above the threshold.

## How to run it

1. **Check what's installed.** The orchestrator degrades gracefully — missing
   scanners are skipped with a warning, never a crash. To install the full set:
   ```bash
   ./install.sh          # native binaries
   # or use the Docker image (see README) for a zero-install run
   ```

2. **Run the scan:**
   ```bash
   python3 scripts/scan.py <repo> [options]
   ```
   Options:
   - `--fail-on {critical|high|medium|low|info}` — CI gate threshold (default `high`)
   - `--baseline findings.sarif` — only findings NEW vs the baseline count toward the gate
   - `--out DIR` — where to write outputs (default: cwd)
   - `--no-triage` — force-skip the AI layer even if a key is set
   - `--target URL` — **opt-in DAST** against a running app you own (see below)
   - `--spec PATH` — OpenAPI spec for API fuzzing (used with `--target`)

3. **Read the outputs:**
   - `security-report.md` — exec summary (counts by severity), a coverage
     section (what ran / was skipped / wasn't tested), findings grouped by
     severity with file:line + fix, and a separate **"needs human review"**
     section for AI-semantic findings.
   - `findings.sarif` — merged, triaged SARIF 2.1.0 (renders in GitHub code
     scanning).
   - **Exit code:** `0` if nothing at/above `--fail-on`, non-zero otherwise.

## The AI triage layer (optional)

Runs only if `ANTHROPIC_API_KEY` is set and the `anthropic` SDK is installed;
otherwise it's skipped cleanly and the raw normalized findings are still
produced. Model defaults to `claude-sonnet-4-6` (override via
`triage.model` in config or the `CLAUDE_SECURITY_MODEL` env var). Three jobs:
false-positive filter + dedupe, severity re-rank, and an **add-only** semantic
pass for authz/logic/config gaps. All repo content is treated as untrusted
data; the semantic pass can only add findings, never suppress. Secret values
are redacted before anything is sent to the API.

## DAST is opt-in and requires authorization

DAST scanners (`schemathesis`, `zap-baseline`) run **only** when you pass
`--target <url>` of a **running app you own or are authorized to test**. Never
point them at systems you don't control.

## Config

Drop a `security.config.yaml` in the target repo to tune enabled scanners,
`fail_on`, ignored paths, per-scanner timeouts, and a suppressions list (each
suppression requires a justification). See the example in this skill's root.

## Adding a scanner

Subclass `Scanner` in `scanners/`, implement `applicable`, `command`, and
`parse` (returning `Finding` objects), and register it in
`scanners/__init__.py`. The base class handles availability checks, timeouts,
and graceful failure. See CONTRIBUTING.md.
