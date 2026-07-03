"""Base class every scanner wrapper inherits.

Contract:
- `applicable(profile)` — should this scanner run for this repo?
- `available()`        — is the binary installed?
- `run(repo)`          — execute with a hard timeout, parse output into
                         normalized Finding objects. Never raises: any
                         failure is reported as a ScanResult with status.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
from findings import Finding  # noqa: E402

DEFAULT_TIMEOUT = 300  # seconds; overridable per scanner via config


@dataclass
class ScanResult:
    scanner: str
    status: str                      # ran | skipped_missing | skipped_not_applicable | timeout | error
    findings: list[Finding] = field(default_factory=list)
    detail: str = ""


class Scanner:
    name: str = "base"
    binary: str = ""                 # executable checked with shutil.which
    category: str = ""               # sast | sca | secrets | iac | container | dast
    timeout: int = DEFAULT_TIMEOUT

    def __init__(self, config: dict | None = None):
        cfg = (config or {}).get("scanners", {}).get(self.name, {})
        self.enabled = cfg.get("enabled", True)
        self.timeout = int(cfg.get("timeout", self.timeout))
        self.extra_args = cfg.get("args", [])

    # --- hooks subclasses implement -------------------------------------
    def applicable(self, profile) -> bool:  # RepoProfile
        return True

    def command(self, repo: Path) -> list[str]:
        raise NotImplementedError

    def parse(self, stdout: str, stderr: str, returncode: int, repo: Path) -> list[Finding]:
        raise NotImplementedError

    # --- shared machinery -------------------------------------------------
    def available(self) -> bool:
        return bool(self.binary) and shutil.which(self.binary) is not None

    def run(self, repo: Path, profile) -> ScanResult:
        if not self.enabled:
            return ScanResult(self.name, "skipped_not_applicable", detail="disabled in config")
        if not self.applicable(profile):
            return ScanResult(self.name, "skipped_not_applicable", detail="not applicable to this repo")
        if not self.available():
            return ScanResult(self.name, "skipped_missing",
                              detail=f"`{self.binary}` not found on PATH — install it or run via Docker (see install.sh)")
        try:
            cmd = self.command(repo) + list(self.extra_args)
            proc = subprocess.run(
                cmd, cwd=str(repo), capture_output=True, text=True,
                timeout=self.timeout,
            )
            findings = self.parse(proc.stdout, proc.stderr, proc.returncode, repo)
            return ScanResult(self.name, "ran", findings=findings,
                              detail=f"{len(findings)} finding(s)")
        except subprocess.TimeoutExpired:
            return ScanResult(self.name, "timeout",
                              detail=f"exceeded {self.timeout}s — treated as skipped; raise timeout in security.config.yaml")
        except Exception as e:  # never crash the pipeline for one tool
            return ScanResult(self.name, "error", detail=f"{type(e).__name__}: {e}")
