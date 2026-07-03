"""Load security.config.yaml with sane defaults. YAML is optional; if PyYAML
isn't installed or no file exists, defaults are used."""

from __future__ import annotations

from pathlib import Path

DEFAULTS = {
    "fail_on": "high",              # critical|high|medium|low|info
    "ignore_paths": [],             # glob patterns excluded from reporting
    "scanners": {},                 # per-scanner {enabled, timeout, args, image}
    "suppressions": [],             # [{fingerprint, justification}]
    "triage": {
        "enabled": True,            # still requires ANTHROPIC_API_KEY
        "model": "claude-sonnet-4-6",
        "max_findings": 200,        # cap sent to the API (cost control)
        "batch_size": 15,
    },
}


def _deep_merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config(repo: str | Path) -> dict:
    path = Path(repo) / "security.config.yaml"
    if not path.is_file():
        return dict(DEFAULTS)
    try:
        import yaml
    except ImportError:
        print("[config] PyYAML not installed; using defaults "
              "(pip install pyyaml to enable security.config.yaml)")
        return dict(DEFAULTS)
    try:
        user = yaml.safe_load(path.read_text()) or {}
    except Exception as e:
        print(f"[config] failed to parse {path}: {e}; using defaults")
        return dict(DEFAULTS)

    cfg = _deep_merge(DEFAULTS, user)

    # Enforce: every suppression must carry a justification.
    valid = []
    for s in cfg.get("suppressions", []) or []:
        if not isinstance(s, dict) or not s.get("fingerprint"):
            continue
        if not s.get("justification"):
            print(f"[config] ignoring suppression {s.get('fingerprint')} "
                  "— missing required 'justification'")
            continue
        valid.append(s)
    cfg["suppressions"] = valid
    return cfg
