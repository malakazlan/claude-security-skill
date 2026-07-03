# claude-security

A **security audit orchestrator** for code repositories. Point it at a repo and
it runs battle-tested open-source scanners, normalizes their output to SARIF,
then uses an optional AI triage layer to filter false positives, re-rank by real
risk, and catch vulnerability classes scanners structurally miss — broken
authorization, business-logic flaws, and insecure configuration. It outputs one
clean report, a machine-readable SARIF file, and a **pass/fail exit code** so it
can gate a CI pipeline.

Packaged as a [Claude Code skill](SKILL.md), but the orchestrator is a plain
Python CLI you can run anywhere.

## Deterministic-first philosophy

The scanners are the source of truth. The AI layer **never invents**
deterministic findings — it only triages, ranks, explains, and reasons about
semantic gaps on top of real code that a scanner already surfaced or a route it
was pointed at. Four principles the tool holds to:

1. **Deterministic-first** — real tools find the issues; AI reasons on top.
2. **Graceful degradation** — a missing scanner is skipped with a warning, never
   a crash. The report lists exactly what ran and what didn't.
3. **Offline-capable core** — all deterministic scanning works with no network
   and no API key. The AI layer is strictly optional.
4. **No false confidence** — every report states its coverage limits plainly.

> ⚠️ **This is not a security guarantee.** A clean result means the configured
> scanners found nothing at or above your threshold — not that your code is
> secure. Treat it as one input to a review process, not a sign-off.

## Install

```bash
git clone https://github.com/your-org/claude-security
cd claude-security
./install.sh          # installs the open-source scanners (versions pinned)
```

Nothing to install is fine too — the tool runs with whatever scanners are
present and skips the rest. To enable the AI layer, set `ANTHROPIC_API_KEY`.

### Docker alternative

If you'd rather not install scanners natively, run the whole thing in a
container that already has them:

```bash
docker run --rm -v "$PWD":/repo -w /app \
  -e ANTHROPIC_API_KEY \
  ghcr.io/your-org/claude-security:latest \
  python3 scripts/scan.py /repo
```

## Quickstart

```bash
# Scan a repo, fail CI on high+ findings (the default)
python3 scripts/scan.py /path/to/repo

# Only fail on NEW findings vs a baseline (great for existing codebases)
python3 scripts/scan.py /path/to/repo --baseline findings.sarif

# Opt-in DAST against a running app you OWN
python3 scripts/scan.py /path/to/repo --target https://staging.example.com --spec openapi.yaml
```

Outputs land in the current directory (or `--out DIR`):
`security-report.md` and `findings.sarif`.

## What it runs

| Category | Scanners | Catches |
|----------|----------|---------|
| SAST | semgrep, bandit (Py), gosec (Go), eslint-plugin-security (JS/TS) | injection, unsafe APIs, dangerous patterns |
| Dependencies | osv-scanner, trivy fs | known-vulnerable dependency versions (CVEs) |
| Secrets | gitleaks, trufflehog | leaked keys/tokens in code + git history |
| IaC / config | checkov, trivy config | public buckets, permissive CORS, missing RLS |
| Containers | trivy image | vulnerable base images (opt-in via config) |
| DAST (opt-in) | schemathesis, zap-baseline | live API/behavior flaws (requires `--target`) |
| AI semantic | claude-sonnet-4-6 | broken authz / IDOR, tenant isolation, logic flaws |

## Sample output

Running it on the bundled `examples/vulnerable-app`:

```
[*] scanning examples/vulnerable-app
[*] languages: python; dependency manifests: 1
  ✓ bandit: ran — 5 finding(s)
  ✓ semgrep: ran — ...
  ○ gitleaks: skipped_missing — install it or run via Docker
  ...
[✗] gate FAIL — findings at/above 'high'
```

The report groups findings by severity, gives each a `file:line`, an
explanation, and a concrete fix, and puts AI-semantic findings (like the
missing ownership check on `DELETE /order/<id>`) in their own **"needs human
review"** section — clearly marked as candidates, excluded from the gate count.

## CI gating

Exit code is `0` when nothing sits at/above `--fail-on` (default `high`),
non-zero otherwise. See [`.github/workflows/security.yml`](.github/workflows/security.yml)
for a ready-to-use PR gate that also uploads the SARIF to GitHub code scanning.

## Adding a new scanner

Subclass `Scanner` in `scanners/`, implement three methods, and register it:

```python
from .base import Scanner
from findings import Finding, normalize_severity

class MyScanner(Scanner):
    name = "mytool"; binary = "mytool"; category = "sast"
    def applicable(self, profile): return "python" in profile.languages
    def command(self, repo): return [self.binary, "--json", str(repo)]
    def parse(self, stdout, stderr, rc, repo):
        return [Finding(tool=self.name, rule_id="...", severity="high", ...)]
```

Add it to `CORE_SCANNERS` in `scanners/__init__.py`. The base class handles
availability checks, timeouts, and graceful failure for free. Details in
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE). Note that `trufflehog` is AGPL-3.0; claude-security shells out
to it as a separate process (no linking), but enterprises with policies on AGPL
tooling should be aware it's in the default install set — omit it via config if
needed.

## Security & responsible use

DAST scanners only run when you pass `--target`, and you must own or be
authorized to test that target. Secret values detected during scanning are
redacted before they enter any report, SARIF, or AI request.
