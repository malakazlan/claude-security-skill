# Contributing to claude-security

Thanks for helping make this better. The most valuable contributions are new
scanner integrations, parser fixes for existing scanners, and improvements to
the AI triage prompts.

## Design contracts (please don't break these)

1. **Deterministic-first.** The AI layer never invents deterministic findings.
   If you're adding intelligence, it must triage/rank/explain real scanner
   output or reason over real code — never fabricate a finding from nothing.
2. **Graceful degradation.** Nothing may crash the pipeline. A scanner that's
   missing, times out, or errors becomes a `ScanResult` with the right status,
   not an exception. The base class enforces this; keep your `parse()` total
   (never raise on malformed output — return what you can).
3. **Offline-capable core.** Deterministic scanning must work with no network
   and no API key. Don't add a scanner invocation that requires phoning home by
   default.
4. **No secret leakage.** Secret *values* must be redacted at ingestion and
   must never reach the SARIF, the report, or an AI request.
5. **Fail closed in triage.** Any parse/API error in the AI layer keeps the
   original finding unchanged. The semantic pass may only *add* findings.

## Adding a scanner

1. Create `scanners/mytool.py` with a `Scanner` subclass:

   ```python
   from .base import Scanner
   from findings import Finding, normalize_severity, read_snippet, relpath

   class MyToolScanner(Scanner):
       name = "mytool"          # unique; also the config key
       binary = "mytool"        # checked with shutil.which
       category = "sast"        # sast|sca|secrets|iac|container|dast
       timeout = 300            # seconds

       def applicable(self, profile) -> bool:
           return "python" in profile.languages

       def command(self, repo):
           return [self.binary, "--json", str(repo)]

       def parse(self, stdout, stderr, returncode, repo):
           out = []
           # ... parse stdout, be defensive, never raise ...
           return out
   ```

2. Register it in `scanners/__init__.py` (`CORE_SCANNERS`).
3. Add its version pin to `install.sh`.
4. Map its severity labels — extend `_SEVERITY_MAP` in `scripts/findings.py` if
   it uses labels not already covered. Unknown labels default to `medium`
   (conservative), never `info`.
5. Add a case to `examples/` if it catches a class nothing else does.

### Parser tips

- Prefer the tool's JSON/SARIF output over text. If you must parse text, be
  defensive: tools change formatting between versions.
- Populate `snippet` — it drives the stable fingerprint (survives line shifts)
  and gives the AI layer context. Use `read_snippet(repo, file, line)` if the
  tool doesn't give you the code.
- Set a meaningful `fix` when the tool provides remediation guidance.

## Running the example

```bash
python3 scripts/scan.py examples/vulnerable-app --out /tmp/out
cat /tmp/out/security-report.md
```

The example app intentionally contains a hardcoded secret, a SQL injection, and
a missing-ownership-check (IDOR). A good contribution keeps all three caught.

## Tests

Please add/adjust the lightweight checks in `tests/` when you touch parsing or
normalization. Run them with `python3 -m pytest tests/` (or plain asserts if
pytest isn't available).

## Style

- Standard library only for the core runtime path. Optional features (YAML
  config, AI triage) may depend on `pyyaml` / `anthropic`, but must degrade
  cleanly when those aren't installed.
- Keep functions total and boring. This is a security tool; clarity beats
  cleverness.
