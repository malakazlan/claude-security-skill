"""DAST wrappers: schemathesis, zap-baseline.

These are OPT-IN ONLY and require an explicit --target the user owns. The
orchestrator constructs them with a target; without one they are never
instantiated.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .base import Scanner
from findings import Finding, normalize_severity


class SchemathesisScanner(Scanner):
    name = "schemathesis"
    binary = "schemathesis"
    category = "dast"
    timeout = 900

    def __init__(self, config=None, target: str = "", spec: str = ""):
        super().__init__(config)
        self.target = target
        self.spec = spec  # path or URL to OpenAPI spec

    def applicable(self, profile) -> bool:
        return bool(self.target) and (bool(self.spec) or profile.has_openapi)

    def command(self, repo: Path) -> list[str]:
        spec = self.spec
        if not spec and repo:
            # fall back to first detected spec
            from detect import detect
            p = detect(repo)
            spec = p.openapi_files[0] if p.openapi_files else ""
        return [self.binary, "run", spec or self.target,
                "--base-url", self.target, "--checks", "all",
                "--report", "-", "--hypothesis-max-examples", "20"]

    def parse(self, stdout, stderr, returncode, repo):
        out = []
        # schemathesis text output: capture FAILED checks heuristically
        for m in re.finditer(r"(\d+)\.\s+(.+?)\s+FAILED", stdout or ""):
            out.append(Finding(
                tool=self.name,
                rule_id="schemathesis.check",
                severity="high",
                file=self.target, line=1,
                message=f"API contract/behavior failure: {m.group(2).strip()}"[:500],
                snippet=m.group(0)[:200],
                fix="Investigate the failing endpoint; enforce input "
                    "validation and correct error handling.",
                tags=["dast", "api"],
            ))
        return out


class ZapBaselineScanner(Scanner):
    name = "zap-baseline"
    binary = "zap-baseline.py"
    category = "dast"
    timeout = 900

    def __init__(self, config=None, target: str = ""):
        super().__init__(config)
        self.target = target

    def applicable(self, profile) -> bool:
        return bool(self.target)

    def command(self, repo: Path) -> list[str]:
        return [self.binary, "-t", self.target, "-J", "/dev/stdout", "-I"]

    def parse(self, stdout, stderr, returncode, repo):
        out = []
        try:
            start = stdout.index("{")
            data = json.loads(stdout[start:])
        except (ValueError, json.JSONDecodeError):
            return out
        for site in data.get("site", []) or []:
            for a in site.get("alerts", []) or []:
                risk = {"3": "high", "2": "medium", "1": "low", "0": "info"}.get(
                    str(a.get("riskcode", "1")), "medium")
                out.append(Finding(
                    tool=self.name,
                    rule_id=f"zap.{a.get('pluginid', 'alert')}",
                    severity=risk,
                    file=self.target, line=1,
                    message=(a.get("alert") or "")[:500],
                    snippet=(a.get("desc") or "")[:200],
                    fix=re.sub(r"<[^>]+>", "", a.get("solution", ""))[:300],
                    tags=["dast"],
                ))
        return out
