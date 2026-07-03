"""SAST wrappers: semgrep, bandit, gosec, eslint(+plugin-security)."""

from __future__ import annotations

import json
from pathlib import Path

from .base import Scanner
from findings import Finding, normalize_severity, read_snippet, relpath


class SemgrepScanner(Scanner):
    name = "semgrep"
    binary = "semgrep"
    category = "sast"
    timeout = 600

    # NOTE: deliberately NOT `--config auto`. Auto fetches rules over the
    # network and reports metrics, which breaks the offline-capable core.
    # `p/security-audit` + `p/secrets` are cached after first fetch; users can
    # vendor rules and point `args: ["--config", "path/to/rules"]` in config
    # for fully air-gapped runs.
    def command(self, repo: Path) -> list[str]:
        return [
            self.binary, "scan",
            "--config", "p/security-audit",
            "--metrics", "off",
            "--json", "--quiet",
            str(repo),
        ]

    def parse(self, stdout, stderr, returncode, repo):
        out = []
        data = json.loads(stdout or "{}")
        for r in data.get("results", []):
            file = relpath(r.get("path", ""), repo)
            line = int(r.get("start", {}).get("line", 1))
            sev = normalize_severity(r.get("extra", {}).get("severity"))
            out.append(Finding(
                tool=self.name,
                rule_id=r.get("check_id", "semgrep.rule"),
                severity=sev,
                file=file,
                line=line,
                message=r.get("extra", {}).get("message", "").strip()[:500],
                snippet=r.get("extra", {}).get("lines", "") or read_snippet(repo, file, line),
                fix=(r.get("extra", {}).get("fix") or ""),
                tags=["sast"],
            ))
        return out


class BanditScanner(Scanner):
    name = "bandit"
    binary = "bandit"
    category = "sast"

    def applicable(self, profile) -> bool:
        return "python" in profile.languages

    def command(self, repo: Path) -> list[str]:
        return [self.binary, "-r", str(repo), "-f", "json", "-q",
                "-x", "node_modules,.venv,venv,.git"]

    def parse(self, stdout, stderr, returncode, repo):
        out = []
        data = json.loads(stdout or "{}")
        for r in data.get("results", []):
            file = relpath(r.get("filename", ""), repo)
            line = int(r.get("line_number", 1))
            out.append(Finding(
                tool=self.name,
                rule_id=r.get("test_id", "bandit.rule"),
                severity=normalize_severity(r.get("issue_severity")),
                file=file,
                line=line,
                message=r.get("issue_text", "").strip()[:500],
                snippet=r.get("code", "") or read_snippet(repo, file, line),
                tags=["sast"],
            ))
        return out


class GosecScanner(Scanner):
    name = "gosec"
    binary = "gosec"
    category = "sast"

    def applicable(self, profile) -> bool:
        return "go" in profile.languages

    def command(self, repo: Path) -> list[str]:
        return [self.binary, "-fmt", "json", "-quiet", "./..."]

    def parse(self, stdout, stderr, returncode, repo):
        out = []
        data = json.loads(stdout or "{}")
        for r in data.get("Issues", []):
            file = relpath(r.get("file", ""), repo)
            line = int(str(r.get("line", "1")).split("-")[0])
            out.append(Finding(
                tool=self.name,
                rule_id=r.get("rule_id", "gosec.rule"),
                severity=normalize_severity(r.get("severity")),
                file=file,
                line=line,
                message=r.get("details", "").strip()[:500],
                snippet=r.get("code", "") or read_snippet(repo, file, line),
                tags=["sast"],
            ))
        return out


class EslintSecurityScanner(Scanner):
    name = "eslint-security"
    binary = "eslint"
    category = "sast"

    def applicable(self, profile) -> bool:
        return bool({"javascript", "typescript"} & profile.languages)

    def command(self, repo: Path) -> list[str]:
        # Relies on the target repo's own eslint config including
        # eslint-plugin-security; we do not inject config into other people's
        # projects. If the plugin isn't configured, results are best-effort.
        return [self.binary, ".", "-f", "json", "--no-error-on-unmatched-pattern"]

    def parse(self, stdout, stderr, returncode, repo):
        out = []
        data = json.loads(stdout or "[]")
        for f in data:
            file = relpath(f.get("filePath", ""), repo)
            for m in f.get("messages", []):
                rule = m.get("ruleId") or ""
                if "security" not in rule:   # only keep security-plugin rules
                    continue
                line = int(m.get("line", 1) or 1)
                sev = "high" if m.get("severity") == 2 else "medium"
                out.append(Finding(
                    tool=self.name, rule_id=rule, severity=sev,
                    file=file, line=line,
                    message=(m.get("message") or "").strip()[:500],
                    snippet=read_snippet(repo, file, line),
                    tags=["sast"],
                ))
        return out
