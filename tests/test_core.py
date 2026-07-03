"""Lightweight tests. Run: python3 -m pytest tests/  (or: python3 tests/test_core.py)"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))

from findings import Finding, normalize_severity
from normalize import (dedupe, to_sarif, load_baseline, apply_suppressions,
                       apply_ignore_paths)
from triage import _parse_json


def test_severity_normalization():
    assert normalize_severity("ERROR") == "high"
    assert normalize_severity("moderate") == "medium"
    assert normalize_severity("blocker") == "critical"
    assert normalize_severity(None) == "medium"      # conservative default
    assert normalize_severity("weird-label") == "medium"


def test_fingerprint_survives_line_shift():
    a = Finding("t", "r", "high", "f.py", 10, "m", snippet="dangerous(x)")
    b = Finding("t", "r", "high", "f.py", 42, "m", snippet="dangerous(x)")
    assert a.fingerprint == b.fingerprint          # same snippet, diff line


def test_distinct_rules_same_line_not_deduped():
    a = Finding("bandit", "B201", "high", "app.py", 50, "debug", snippet="app.run(debug=True)")
    b = Finding("bandit", "B104", "medium", "app.py", 50, "bind", snippet="app.run(debug=True)")
    out = dedupe([a, b])
    assert len(out) == 2                            # different rules => 2 findings


def test_exact_duplicate_collapsed():
    a = Finding("bandit", "B105", "low", "app.py", 16, "secret", snippet="KEY = '...'")
    b = Finding("bandit", "B105", "low", "app.py", 16, "secret", snippet="KEY = '...'")
    out = dedupe([a, b])
    assert len(out) == 1


def test_cross_tool_corroboration_tag():
    a = Finding("semgrep", "sqli", "high", "app.py", 30, "sqli", snippet="q = '...%s' % x")
    b = Finding("bandit", "B608", "medium", "app.py", 30, "sqli", snippet="q = '...%s' % x")
    out = dedupe([a, b])
    assert len(out) == 2
    tags = " ".join(t for f in out for t in f.tags)
    assert "also:semgrep" in tags or "also:bandit" in tags


def test_sarif_shape():
    f = Finding("bandit", "B105", "low", "app.py", 16, "secret", snippet="x")
    doc = to_sarif([f])
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"][0]["ruleId"] == "B105"
    fp = doc["runs"][0]["results"][0]["partialFingerprints"]["csFingerprint"]
    assert fp == f.fingerprint


def test_baseline_suppresses_in_sarif():
    f = Finding("bandit", "B105", "high", "app.py", 16, "secret", snippet="x")
    doc = to_sarif([f], baseline={f.fingerprint})
    res = doc["runs"][0]["results"][0]
    assert res["properties"]["inBaseline"] is True
    assert "suppressions" in res


def test_suppression_marks_finding():
    f = Finding("bandit", "B105", "high", "app.py", 16, "secret", snippet="x")
    apply_suppressions([f], [{"fingerprint": f.fingerprint, "justification": "test fixture"}])
    assert f.suppressed is True
    assert "test fixture" in f.suppress_reason


def test_ignore_paths_drops_matching_findings():
    kept = Finding("gitleaks", "aws", "high", "src/app.py", 3, "key")
    ignored = Finding("gitleaks", "aws", "high", "examples/vulnerable-app/app.py", 16, "key")
    out = apply_ignore_paths([kept, ignored], ["examples/**"])
    assert out == [kept]


def test_ignore_paths_handles_windows_separators():
    f = Finding("gitleaks", "aws", "high", "examples\\vulnerable-app\\app.py", 16, "key")
    assert apply_ignore_paths([f], ["examples/**"]) == []


def test_ignore_paths_nested_glob():
    f = Finding("semgrep", "r", "high", "static/js/vendor/lib.min.js", 1, "m")
    assert apply_ignore_paths([f], ["**/*.min.js"]) == []


def test_ignore_paths_empty_patterns_keeps_all():
    f = Finding("semgrep", "r", "high", "examples/x.py", 1, "m")
    assert apply_ignore_paths([f], []) == [f]


def test_triage_parse_fails_closed():
    assert _parse_json("not json at all") is None
    assert _parse_json("") is None
    assert _parse_json('```json\n[{"index":0,"keep":true}]\n```') == [{"index": 0, "keep": True}]


def test_secret_value_not_in_snippet():
    # secrets scanners must never put the raw secret in snippet/fingerprint input
    from scanners.secrets import GitleaksScanner
    gl = GitleaksScanner()
    findings = gl.parse('[{"RuleID":"aws","File":"c.py","StartLine":3,"Secret":"AKIAREALSECRET1234","Description":"AWS key"}]', "", 0, ROOT)
    assert findings
    for f in findings:
        assert "AKIAREALSECRET1234" not in f.snippet
        assert "AKIAREALSECRET1234" not in f.message


def _run_all():
    fns = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL {fn.__name__}: {e}")
        except Exception as e:
            print(f"  ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
    return passed == len(fns)


if __name__ == "__main__":
    sys.exit(0 if _run_all() else 1)
