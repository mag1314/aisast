"""Unit tests for the deterministic analyzers."""
from aisast.config import Config
from aisast.scanner import scan_sources


def scan(files: dict, **cfg):
    findings, _ = scan_sources(files, Config(**cfg))
    return findings


def rules(fs):
    return sorted((f.file, f.line, f.rule_id) for f in fs)


FLASK = "from flask import Flask, request, redirect\napp = Flask(__name__)\n"


def test_sqli_taint_and_parameterized_safe():
    code = FLASK + '''
@app.route("/a")
def a():
    q = request.args.get("q")
    cur.execute("SELECT * FROM t WHERE n = '" + q + "'")
@app.route("/b")
def b():
    q = request.args.get("q")
    cur.execute("SELECT * FROM t WHERE n = ?", (q,))
'''
    fs = scan({"app.py": code})
    assert [f.rule_id for f in fs] == ["PY-SQLI-TAINT"]
    assert fs[0].line == 7 and fs[0].confidence == "high"
    assert "request.args" in fs[0].trace[0]


def test_interprocedural_cross_file_flow():
    files = {
        "app.py": FLASK + 'from . import db\n@app.route("/u")\ndef u():\n    return db.find(request.form["name"])\n',
        "db.py": 'def find(name):\n    sql = "SELECT * FROM u WHERE n = \'%s\'" % name\n    return conn.execute(sql)\n',
    }
    fs = [f for f in scan(files) if f.category == "sqli"]
    assert len(fs) == 1 and fs[0].file == "db.py" and fs[0].rule_id == "PY-SQLI-TAINT"
    assert any("passed to find()" in t for t in fs[0].trace)


def test_sanitizers_and_constants_are_safe():
    code = FLASK + '''import os, subprocess
from werkzeug.utils import secure_filename
from markupsafe import escape
TABLE = "items"
ALLOWED = {"a", "b"}
@app.route("/x")
def x():
    n = int(request.args["n"])
    cur.execute(f"SELECT * FROM {TABLE} WHERE id = {n}")
    f = secure_filename(request.args["f"])
    open(os.path.join("/data", f))
    s = request.args["s"]
    col = s if s in ALLOWED else "a"
    cur.execute(f"SELECT * FROM t ORDER BY {col}")
    subprocess.run(["ls", request.args["d"]])
    return f"<p>{escape(request.args['name'])}</p>"
'''
    assert scan({"app.py": code}) == []


def test_validation_guard_idiom():
    code = FLASK + '''
@app.route("/r")
def r():
    nxt = request.args.get("next", "/")
    if not nxt.startswith("/") or nxt.startswith("//"):
        nxt = "/"
    return redirect(nxt)
@app.route("/r2")
def r2():
    return redirect(request.args.get("next"))
'''
    fs = scan({"app.py": code})
    assert [(f.rule_id, f.line) for f in fs] == [("PY-OPEN-REDIRECT", 12)]


def test_classic_sinks():
    code = FLASK + '''import os, pickle, yaml, requests
from flask import render_template_string, send_file
@app.route("/z/<name>")
def z(name):
    os.system("ping " + request.args["h"])
    eval(request.form["e"])
    pickle.loads(request.data)
    yaml.load(request.data, Loader=yaml.Loader)
    requests.get(request.args["u"])
    send_file(name)
    render_template_string("<b>" + name + "</b>")
    return f"<h1>{name}</h1>"
'''
    cats = sorted({f.category for f in scan({"app.py": code})})
    assert cats == sorted({"cmdi", "code-injection", "deserialization", "ssrf", "path-traversal", "ssti", "xss"})


def test_patterns_respect_context():
    code = '''import hashlib, random
def cache_key(p):
    return hashlib.md5(p.encode(), usedforsecurity=False).hexdigest()
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()
def shuffle(items):
    return random.sample(items, 2)
def make_token():
    return random.random()
'''
    got = rules(scan({"u.py": code}))
    assert got == [("u.py", 5, "PY-WEAK-HASH"), ("u.py", 9, "PY-INSECURE-RANDOM")]
    strict = rules(scan({"u.py": code}, strict=True))
    assert ("u.py", 7, "PY-INSECURE-RANDOM") in strict


def test_secrets_and_placeholders():
    files = {"config.py": 'SECRET_KEY = "k8Hq2-xP0zLm9Tr4VwYb"\nPASSWORD_FIELD = "password"\nAPI_KEY = "your-api-key"\n',
             ".env": "DB_PASSWORD=Xk29-plq0-ZZ81mm\nTOKEN=changeme\n",
             "keys.txt": "-----BEGIN RSA PRIVATE KEY-----\n"}
    got = rules(scan(files))
    assert got == [(".env", 1, "SECRET-GENERIC"), ("config.py", 1, "PY-HARDCODED-SECRET"), ("keys.txt", 1, "SECRET-PRIVATE-KEY")]


def test_test_files_do_not_report_fixture_credentials():
    assert scan({"tests/test_login.py": 'PASSWORD = "Fixture-Pass-1234!"\n'}) == []


def test_inline_suppression():
    code = FLASK + '@app.route("/a")\ndef a():\n    eval(request.args["x"])  # aisast: ignore\n'
    assert scan({"app.py": code}) == []


def test_javascript_taint_and_sanitizers():
    js = '''const express = require("express"); const app = express();
app.get("/a", (req, res) => {
  const q = req.query.q;
  db.query("SELECT * FROM t WHERE n = '" + q + "'");
  db.query("SELECT * FROM t WHERE n = ?", [q]);
  res.send(`<p>${escapeHtml(q)}</p>`);
  res.send(`<p>${q}</p>`);
  fs.readFile(path.join(__dirname, path.basename(req.query.f)));
  exec("ls " + req.body.dir);
  execFile("ls", [req.body.dir]);
});
'''
    got = [(f.line, f.rule_id) for f in scan({"s.js": js})]
    assert sorted(got) == [(4, "JS-SQLI"), (7, "JS-XSS"), (9, "JS-CMDI")]


def test_fingerprint_stable_across_line_shift():
    code = FLASK + '@app.route("/a")\ndef a():\n    eval(request.args["x"])\n'
    a = scan({"app.py": code})[0]
    b = scan({"app.py": "\n\n# moved\n" + code})[0]
    assert a.fingerprint == b.fingerprint and a.line != b.line
