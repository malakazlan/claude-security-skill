"""Scanner registry. The orchestrator asks for the applicable set."""

from .base import Scanner, ScanResult
from .sast import (SemgrepScanner, BanditScanner, GosecScanner,
                   EslintSecurityScanner)
from .sca import OsvScanner, TrivyFsScanner
from .secrets import GitleaksScanner, TrufflehogScanner
from .iac import CheckovScanner, TrivyConfigScanner, TrivyImageScanner
from .dast import SchemathesisScanner, ZapBaselineScanner

# Everything except DAST (which needs an explicit target and is added
# separately by the orchestrator).
CORE_SCANNERS = [
    SemgrepScanner, BanditScanner, GosecScanner, EslintSecurityScanner,
    OsvScanner, TrivyFsScanner,
    GitleaksScanner, TrufflehogScanner,
    CheckovScanner, TrivyConfigScanner, TrivyImageScanner,
]

__all__ = ["Scanner", "ScanResult", "CORE_SCANNERS",
           "SchemathesisScanner", "ZapBaselineScanner"]
