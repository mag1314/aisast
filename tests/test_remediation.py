"""Remediation engine: templates, validation gates, patches, git output."""
import subprocess
from pathlib import Path

from aisast.config import Config
from aisast.remediate import add_imports, apply_region, generate_fix, plan_groups, reindent, strip_fences
from aisast.scanner import scan_sources
from aisast.templates import parameterize, _flatten_concat
import ast


def fix_all(files):
    cfg = Config()
    fs, _ = scan_sources(files, cfg)
    return [generate_fix(g, files, cfg, None, fs) for g in plan_groups(fs, files)]


def test_parameterize_like_and_quotes():
    node = ast.parse("""f"SELECT * FROM p WHERE name LIKE '%{q}%' AND id = {i}" """).body[0].value
    sql, params = parameterize(_flatten_concat(node), "?")
    assert sql == "SELECT * FROM p WHERE name LIKE ? AND id = ?"
    assert params == ['f"%{q}%"', "i"]


def test_identifier_positions_are_not_parameterized():
    node = ast.parse('f"SELECT * FROM t ORDER BY {col}"').body[0].value
    assert parameterize(_flatten_concat(node), "?") is None


def test_sqli_fix_validated_and_rescanned():
    code = ('import sqlite3\nfrom flask import Flask, request\napp = Flask(__name__)\n'
            '@app.route("/s")\ndef s():\n    q = request.args["q"]\n'
            '    return str(conn.execute(f"SELECT * FROM p WHERE n = \'{q}\'").fetchall())\n')
    [r] = fix_all({"app.py": code})
    assert r.status == "validated" and r.method == "template"
    assert r.validation["syntax"] == "pass" and r.validation["rescan"] == "pass"
    assert 'conn.execute("SELECT * FROM p WHERE n = ?", (q,))' in r.diff
    assert r.diff.startswith("diff --git a/app.py b/app.py")


def test_js_fixes_pass_node_check():
    js = ('const express = require("express"); const app = express();\n'
          'app.get("/a", (req, res) => {\n  const t = req.query.t;\n  res.send(`<b>${t}</b>`);\n});\n')
    [r] = fix_all({"s.js": js})
    assert r.status == "validated" and "escapeHtml(t)" in r.diff and "const escapeHtml" in r.diff


def test_unsupported_without_llm():
    code = 'import requests\nfrom flask import request\n@app.route("/p")\ndef p():\n    return requests.get(request.args["u"]).text\n'
    [r] = fix_all({"a.py": code})
    assert r.status == "unsupported"


def test_reindent_and_fence_stripping():
    original = "    def f():\n        return 1"
    assert reindent("def f():\n    return 2", original) == "    def f():\n        return 2"
    assert strip_fences("```python\n  12 | x = 1\n  13 | y = 2\n```") == "x = 1\ny = 2"


def test_add_imports_dedupes_and_places():
    src = '"""doc"""\nimport os\nfrom x import y\n\nprint(1)\n'
    out = add_imports(src, ["import os", "import secrets", "from x import y"], "python")
    assert out.splitlines()[:4] == ['"""doc"""', "import os", "from x import y", "import secrets"]
    patched, shift = apply_region("a\nb\nc", 2, 2, "B1\nB2", [], "python")
    assert patched == "a\nB1\nB2\nc" and shift == 0


def test_end_to_end_cli_apply_git(tmp_path: Path):
    repo = tmp_path / "proj"
    repo.mkdir()
    (repo / "app.py").write_text('import yaml\nfrom flask import Flask, request\napp = Flask(__name__)\n'
                                 '@app.route("/i", methods=["POST"])\ndef i():\n    return str(yaml.load(request.data, Loader=yaml.Loader))\n')
    git = lambda *a: subprocess.run(["git", *a], cwd=repo, capture_output=True, text=True)
    git("init", "-q"); git("add", "-A"); git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "init")
    from aisast.cli import main
    assert main(["scan", str(repo), "--no-ai", "-q"]) == 0
    assert main(["fix", str(repo), "--no-ai", "--apply", "--git", "-q"]) == 0
    assert "yaml.safe_load(request.data)" in (repo / "app.py").read_text()
    assert "aisast/fix-" in git("branch", "--show-current").stdout
    assert main(["verify", str(repo), "--no-ai"]) == 0
    import json
    state = json.loads((repo / ".aisast" / "state.json").read_text())
    assert [r["status"] for r in state["findings"].values()] == ["verified"]
