"""AI pipeline plumbing against the Ollama test double (tools/mock_ollama.py).

These tests check transport, schemas, caching, guardrails, hallucination filtering and
the fix self-correction loop. They say nothing about model quality.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import mock_ollama  # noqa: E402

from aisast.config import Config  # noqa: E402
from aisast.llm.analysis import _validate_candidate, apply_triage  # noqa: E402
from aisast.llm.ollama import OllamaClient, parse_json  # noqa: E402
from aisast.models import Finding  # noqa: E402
from aisast.pipeline import fix, scan  # noqa: E402

PORT = 11531


@pytest.fixture(scope="module")
def mock():
    srv = mock_ollama.serve(PORT)
    yield f"http://127.0.0.1:{PORT}"
    srv.shutdown()


def test_parse_json_repairs_common_model_output():
    assert parse_json('```json\n{"a": 1,}\n```') == {"a": 1}
    assert parse_json('Sure! {"verdict": "true_positive"} hope this helps') == {"verdict": "true_positive"}
    assert parse_json("no json here") is None


def test_health_and_unreachable():
    h = OllamaClient("http://127.0.0.1:9", timeout=2).health()
    assert not h["ok"] and "ollama serve" in h["message"]


def test_triage_guardrails():
    cfg = Config()
    f = Finding("PY-SQLI-TAINT", "SQL Injection", "critical", "high", "a.py", 3, "m")
    apply_triage(f, {"verdict": "false_positive", "confidence": 0.8, "severity": "info", "explanation": "x"}, cfg)
    assert f.status == "open", "critical findings need >= 0.85 confidence to be suppressed"
    apply_triage(f, {"verdict": "true_positive", "confidence": 0.9, "severity": "low", "explanation": "x"}, cfg)
    assert f.severity == "high", "model may only move severity one level"
    g = Finding("PY-SQLI-FORMAT", "SQL Injection", "medium", "low", "a.py", 3, "m")
    apply_triage(g, {"verdict": "false_positive", "confidence": 0.9, "severity": "info", "explanation": "constant"}, cfg)
    assert g.status == "false_positive"


def test_deep_scan_candidates_are_grounded():
    lines = ["def delete(uid):", "    db.delete_user(uid)"]
    ok = _validate_candidate({"line": 1, "category": "missing-auth", "cwe": "CWE-862", "title": "t", "severity": "high",
                              "confidence": 0.9, "evidence": "db.delete_user(uid)", "description": "d"}, "a.py", "python", lines, 1, 2, [])
    assert ok and ok.line == 2 and ok.rule_id == "AI-MISSING-AUTH"   # snapped to the evidence line
    bad = _validate_candidate({"line": 1, "category": "idor", "cwe": "CWE-639", "title": "t", "severity": "high",
                               "confidence": 0.9, "evidence": "invented_code()", "description": "d"}, "a.py", "python", lines, 1, 2, [])
    assert bad is None
    low = _validate_candidate({"line": 2, "category": "idor", "cwe": "CWE-639", "title": "t", "severity": "high",
                               "confidence": 0.3, "evidence": "db.delete_user(uid)", "description": "d"}, "a.py", "python", lines, 1, 2, [])
    assert low is None


def test_full_ai_scan_and_fix_loop(mock, tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    (proj / "app.py").write_text('import yaml\nfrom flask import Flask, request\napp = Flask(__name__)\n'
                                 '@app.route("/i", methods=["POST"])\ndef i():\n    return str(yaml.load(request.data, Loader=yaml.Loader))\n')
    cfg = Config(ollama_url=mock, deep_scan=True)
    res = scan(proj, cfg, log=lambda m: None)
    assert res.ai["enabled"] and res.ai["summary"]["executive_summary"].startswith("[mock]")
    yaml_f = next(f for f in res.findings if f.rule_id == "PY-DESER-YAML")
    assert yaml_f.ai["verdict"] == "true_positive"
    assert all(f.title != "hallucinated" for f in res.findings), "ungrounded LLM finding must be dropped"
    calls = res.ai["llm_stats"]["calls"]
    res2 = scan(proj, cfg, log=lambda m: None)
    assert res2.ai["llm_stats"]["cache_hits"] >= calls - 1, "second scan should be served from cache"
    out = fix(proj, Config(ollama_url=mock), log=lambda m: None, ids=[yaml_f.id])
    r = out["results"][0]
    # mock returns a syntax error, then an unchanged region -> loop feeds errors back, then falls back to template
    assert r.status == "validated" and r.method == "template" and r.attempts >= 3
    assert any("compile" in e or "Syntax" in e for e in r.errors)
    sarif = json.loads((proj / ".aisast").joinpath("last-scan.json").read_text())
    assert sarif["findings"]
