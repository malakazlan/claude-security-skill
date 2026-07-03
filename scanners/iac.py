"""Infra/config wrappers: checkov, trivy config, trivy image."""

from __future__ import annotations

import json
from pathlib import Path

from .base import Scanner
from findings import Finding, normalize_severity, read_snippet, relpath


class CheckovScanner(Scanner):
    name = "checkov"
    binary = "checkov"
    category = "iac"
    timeout = 600

    def applicable(self, profile) -> bool:
        return profile.has_iac or profile.has_dockerfile

    def command(self, repo: Path) -> list[str]:
        return [self.binary, "-d", str(repo), "-o", "json", "--quiet",
                "--compact"]

    def parse(self, stdout, stderr, returncode, repo):
        out = []
        data = json.loads(stdout or "{}")
        blobs = data if isinstance(data, list) else [data]
        for blob in blobs:
            for r in (blob.get("results", {}) or {}).get("failed_checks", []):
                file = (r.get("file_path") or "").lstrip("/")
                rng = r.get("file_line_range") or [1]
                line = int(rng[0] or 1)
                out.append(Finding(
                    tool=self.name,
                    rule_id=r.get("check_id", "checkov.rule"),
                    severity=normalize_severity(r.get("severity") or "medium"),
                    file=file, line=line,
                    message=(r.get("check_name") or "").strip()[:500],
                    snippet=read_snippet(repo, file, line, context=1),
                    fix=(r.get("guideline") and
                         f"See guideline: {r['guideline']}") or "",
                    tags=["iac", "config"],
                ))
        return out


class _TrivyBase(Scanner):
    binary = "trivy"
    timeout = 600

    def _parse_trivy(self, stdout, repo, tag):
        out = []
        data = json.loads(stdout or "{}")
        for res in data.get("Results", []) or []:
            target = res.get("Target", "")
            for m in res.get("Misconfigurations", []) or []:
                line = int((m.get("CauseMetadata", {}) or {}).get("StartLine", 1) or 1)
                out.append(Finding(
                    tool=self.name,
                    rule_id=m.get("ID", "trivy.misconfig"),
                    severity=normalize_severity(m.get("Severity")),
                    file=target, line=line,
                    message=(m.get("Title") or m.get("Message") or "")[:500],
                    snippet=read_snippet(repo, target, line, context=1),
                    fix=(m.get("Resolution") or ""),
                    tags=[tag, "config"],
                ))
            for v in res.get("Vulnerabilities", []) or []:
                out.append(Finding(
                    tool=self.name,
                    rule_id=v.get("VulnerabilityID", "trivy.vuln"),
                    severity=normalize_severity(v.get("Severity")),
                    file=target, line=1,
                    message=(f"{v.get('PkgName')}@{v.get('InstalledVersion')}: "
                             f"{v.get('Title') or v.get('VulnerabilityID')}")[:500],
                    snippet=f"{v.get('PkgName')}=={v.get('InstalledVersion')}",
                    fix=(f"Upgrade to {v.get('FixedVersion')}"
                         if v.get("FixedVersion") else ""),
                    tags=[tag],
                ))
        return out


class TrivyConfigScanner(_TrivyBase):
    name = "trivy-config"
    category = "iac"

    def applicable(self, profile) -> bool:
        return profile.has_iac or profile.has_dockerfile

    def command(self, repo: Path) -> list[str]:
        return [self.binary, "config", "--format", "json", "--quiet", str(repo)]

    def parse(self, stdout, stderr, returncode, repo):
        return self._parse_trivy(stdout, repo, "iac")


class TrivyImageScanner(_TrivyBase):
    name = "trivy-image"
    category = "container"
    timeout = 900

    def __init__(self, config=None):
        super().__init__(config)
        cfg = (config or {}).get("scanners", {}).get(self.name, {})
        self.image = cfg.get("image", "")  # explicit image name from config

    def applicable(self, profile) -> bool:
        # Only runs when an image name is explicitly configured; building or
        # guessing images on the user's behalf is out of scope.
        return bool(self.image)

    def command(self, repo: Path) -> list[str]:
        return [self.binary, "image", "--format", "json", "--quiet", self.image]

    def parse(self, stdout, stderr, returncode, repo):
        return self._parse_trivy(stdout, repo, "container")
