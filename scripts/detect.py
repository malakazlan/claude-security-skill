"""Detect languages, package ecosystems, and infrastructure files in a repo.

Pure filesystem inspection — no network, no scanner dependencies. The result
drives which scanners the orchestrator attempts to run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

# Directories never worth walking into
SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".tox",
    "dist", "build", ".next", ".nuxt", "target", "vendor", ".terraform",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "site-packages",
}

LANG_EXTS = {
    "python": {".py"},
    "go": {".go"},
    "javascript": {".js", ".jsx", ".mjs", ".cjs"},
    "typescript": {".ts", ".tsx"},
    "java": {".java"},
    "ruby": {".rb"},
    "php": {".php"},
    "c": {".c", ".h"},
    "cpp": {".cpp", ".cc", ".hpp"},
    "csharp": {".cs"},
    "rust": {".rs"},
    "shell": {".sh", ".bash"},
}

DEP_MANIFESTS = {
    "requirements.txt", "Pipfile.lock", "poetry.lock", "uv.lock",
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "go.mod", "go.sum", "Cargo.lock", "Gemfile.lock", "composer.lock",
    "pom.xml", "build.gradle", "build.gradle.kts",
}

IAC_MARKERS = {
    ".tf", ".tfvars",              # terraform (extensions)
}
IAC_FILENAMES = {
    "serverless.yml", "serverless.yaml", "cloudformation.yaml",
    "cloudformation.yml", "template.yaml", "template.yml",
}
K8S_HINTS = ("apiVersion:", "kind:")


@dataclass
class RepoProfile:
    languages: set[str] = field(default_factory=set)
    has_dependencies: bool = False
    dep_files: list[str] = field(default_factory=list)
    has_dockerfile: bool = False
    dockerfiles: list[str] = field(default_factory=list)
    has_iac: bool = False
    iac_files: list[str] = field(default_factory=list)
    has_git: bool = False
    has_openapi: bool = False
    openapi_files: list[str] = field(default_factory=list)
    file_count: int = 0

    def summary(self) -> str:
        parts = []
        if self.languages:
            parts.append("languages: " + ", ".join(sorted(self.languages)))
        if self.has_dependencies:
            parts.append(f"dependency manifests: {len(self.dep_files)}")
        if self.has_dockerfile:
            parts.append(f"dockerfiles: {len(self.dockerfiles)}")
        if self.has_iac:
            parts.append(f"IaC files: {len(self.iac_files)}")
        if self.has_git:
            parts.append("git history present")
        if self.has_openapi:
            parts.append("OpenAPI spec present")
        return "; ".join(parts) or "empty or unrecognized repo"


def _looks_like_openapi(path: Path) -> bool:
    if path.suffix.lower() not in {".json", ".yaml", ".yml"}:
        return False
    if not any(k in path.name.lower() for k in ("openapi", "swagger", "api")):
        return False
    try:
        head = path.read_text(errors="replace")[:2000]
        return "openapi" in head or "swagger" in head
    except Exception:
        return False


def _looks_like_k8s(path: Path) -> bool:
    if path.suffix.lower() not in {".yaml", ".yml"}:
        return False
    try:
        head = path.read_text(errors="replace")[:2000]
        return all(h in head for h in K8S_HINTS)
    except Exception:
        return False


def detect(repo: str | Path) -> RepoProfile:
    repo = Path(repo)
    profile = RepoProfile()
    profile.has_git = (repo / ".git").exists()

    ext_to_lang = {}
    for lang, exts in LANG_EXTS.items():
        for e in exts:
            ext_to_lang.setdefault(e, set()).add(lang)

    for path in repo.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        profile.file_count += 1
        rel = str(path.relative_to(repo))
        name, ext = path.name, path.suffix.lower()

        for lang in ext_to_lang.get(ext, ()):
            profile.languages.add(lang)

        if name in DEP_MANIFESTS:
            profile.has_dependencies = True
            profile.dep_files.append(rel)

        if name == "Dockerfile" or name.startswith("Dockerfile."):
            profile.has_dockerfile = True
            profile.dockerfiles.append(rel)

        if ext in IAC_MARKERS or name in IAC_FILENAMES or _looks_like_k8s(path):
            profile.has_iac = True
            profile.iac_files.append(rel)

        if _looks_like_openapi(path):
            profile.has_openapi = True
            profile.openapi_files.append(rel)

    return profile


if __name__ == "__main__":
    import sys
    p = detect(sys.argv[1] if len(sys.argv) > 1 else ".")
    print(p.summary())
