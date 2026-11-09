"""Reports (JSON/SARIF/Markdown/HTML) and remediation tracking."""
import json
from pathlib import Path

from aisast.config import Config
from aisast.pipeline import scan, write_reports
from aisast.tracking import load_state, set_status

VULN = 'from flask import Flask, request\napp = Flask(__name__)\n@app.route("/a")\ndef a():\n    return eval(request.args["x"])\n'


def test_reports_and_lifecycle(tmp_path: Path):
    (tmp_path / "app.py").write_text(VULN)
    cfg = Config(ai_enabled=False)
    res = scan(tmp_path, cfg, log=lambda m: None)
    assert res.tracking["new"] == 1
    paths = write_reports(tmp_path, res, cfg, ["html", "json", "sarif", "md"])
    assert {p.suffix for p in paths} == {".html", ".json", ".sarif", ".md"}
    sarif = json.loads((tmp_path / ".aisast/reports/aisast-report.sarif").read_text())
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and run["results"][0]["ruleId"] == "PY-CODE-EVAL"
    assert run["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"]
    assert run["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "9.5"
    html = (tmp_path / ".aisast/reports/aisast-report.html").read_text()
    assert "Code Injection" in html and "<script>" in html
    fid = res.findings[0].id

    # human marks accepted risk -> survives re-scan
    set_status(tmp_path, fid, "accepted_risk", "internal tool")
    res = scan(tmp_path, cfg, log=lambda m: None)
    assert res.findings[0].status == "accepted_risk" and res.tracking["existing"] == 1

    # code fixed -> verified; code reintroduced -> reopened
    set_status(tmp_path, fid, "open")
    (tmp_path / "app.py").write_text(VULN.replace('eval(request.args["x"])', '"ok"'))
    res = scan(tmp_path, cfg, log=lambda m: None)
    assert res.tracking["resolved"] == 1 and res.findings == []
    (tmp_path / "app.py").write_text(VULN)
    res = scan(tmp_path, cfg, log=lambda m: None)
    assert res.findings[0].status == "reopened" and res.tracking["reopened"] == 1
    hist = [h["status"] for h in next(iter(load_state(tmp_path)["findings"].values()))["history"]]
    assert hist == ["open", "accepted_risk", "open", "verified", "reopened"]
