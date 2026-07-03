"""Dependency / SCA wrappers: osv-scanner, trivy fs."""

from __future__ import annotations

import json
from pathlib import Path

from .base import Scanner
from findings import Finding, normalize_severity, relpath


class OsvScanner(Scanner):
    name = "osv-scanner"
    binary = "osv-scanner"
    category = "sca"

    def applicable(self, profile) -> bool:
        return profile.has_dependencies

    def command(self, repo: Path) -> list[str]:
        return [self.binary, "--format", "json", "-r", str(repo)]

    def parse(self, stdout, stderr, returncode, repo):
        out = []
        data = json.loads(stdout or "{}")
        for res in data.get("results", []):
            src = relpath(res.get("source", {}).get("path", ""), repo)
            for pkg in res.get("packages", []):
                p = pkg.get("package", {})
                for vuln in pkg.get("vulnerabilities", []):
                    sev = "medium"
                    for s in vuln.get("severity", []) or []:
                        # CVSS vector -> coarse bucket by score if present
                        score = s.get("score", "")
                        try:
                            v = float(str(score).split("/")[0])
                            sev = ("critical" if v >= 9 else "high" if v >= 7
                                   else "medium" if v >= 4 else "low")
                        except (ValueError, IndexError):
                            pass
                    db = vuln.get("database_specific", {}) or {}
                    if db.get("severity"):
                        sev = normalize_severity(db["severity"])
                    out.append(Finding(
                        tool=self.name,
                        rule_id=vuln.get("id", "OSV"),
                        severity=sev,
                        file=src, line=1,
                        message=(f"{p.get('name')}@{p.get('version')}: "
                                 f"{vuln.get('summary') or vuln.get('id')}")[:500],
                        snippet=f"{p.get('name')}=={p.get('version')}",
                        fix="Upgrade to a patched version (see advisory "
                            f"{vuln.get('id')}).",
                        tags=["sca", "dependency"],
                    ))
        return out


class TrivyFsScanner(Scanner):
    name = "trivy-fs"
    binary = "trivy"
    category = "sca"
    timeout = 600

    def applicable(self, profile) -> bool:
        return profile.has_dependencies

    def command(self, repo: Path) -> list[str]:
        return [self.binary, "fs", "--scanners", "vuln", "--format", "json",
                "--quiet", str(repo)]

    def parse(self, stdout, stderr, returncode, repo):
        out = []
        data = json.loads(stdout or "{}")
        for res in data.get("Results", []) or []:
            target = res.get("Target", "")
            for v in res.get("Vulnerabilities", []) or []:
                out.append(Finding(
                    tool=self.name,
                    rule_id=v.get("VulnerabilityID", "trivy.vuln"),
                    severity=normalize_severity(v.get("Severity")),
                    file=target, line=1,
                    message=(f"{v.get('PkgName')}@{v.get('InstalledVersion')}: "
                             f"{v.get('Title') or v.get('VulnerabilityID')}")[:500],
                    snippet=f"{v.get('PkgName')}=={v.get('InstalledVersion')}",
                    fix=(f"Upgrade {v.get('PkgName')} to "
                         f"{v.get('FixedVersion')}" if v.get("FixedVersion")
                         else "No fixed version published yet; assess exposure."),
                    tags=["sca", "dependency"],
                ))
        return out
