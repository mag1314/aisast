# End-to-end demo

The demo scans **AcmeShop** (`demo/vulnerable-app`): a Flask shop, an Express partner API and a
browser script containing 44 labelled vulnerabilities (`ground_truth.json`) and 24 safe look-alikes,
plus 10 functional tests that must keep passing after remediation.

| file | contents |
|---|---|
| `app/main.py` | 30+ Flask routes: SQLi, XSS, SSTI, path traversal, SSRF, open redirect, pickle/YAML, `eval`, command injection, JWT without verification, IDOR, missing authorization, mass assignment, a business-logic flaw — and safe variants of most of them |
| `app/db.py` | data layer; `find_user()` is SQL-injectable only via the call in `main.py` (cross-file flow) |
| `app/config.py`, `.env` | hardcoded secrets, AWS key, a placeholder that must not be flagged |
| `app/utils.py` | weak OTP randomness, `mktemp`, `shell=True`, safe MD5 cache key |
| `web/server.js`, `web/public/app.js` | Express SQLi/NoSQLi/`exec`/XSS/SSRF/`eval`/prototype pollution/`node-serialize`/`jwt.decode`, DOM XSS |
| `tests/test_app.py` | functional tests (legitimate behaviour only) |

## Prerequisites

```bash
pip install -e .                                      # AI-SAST (stdlib only)
pip install -r demo/vulnerable-app/requirements.txt   # flask, pyyaml, requests, pyjwt, pytest — for the tests
ollama serve & ollama pull qwen2.5-coder:7b           # for the AI stages (optional: the demo degrades gracefully)
```

## One command

```bash
./demo/run_demo.sh                      # full AI workflow
./demo/run_demo.sh --model qwen2.5-coder:14b
./demo/run_demo.sh --no-ai              # deterministic engine + fix templates only
```

The script copies the app to `/tmp/aisast-demo`, makes it a git repository, and runs:

| step | command | what happens |
|---|---|---|
| 0 | — | fresh copy, `git init`, functional tests pass on the vulnerable code |
| 1 | `aisast doctor` | Ollama reachable? model pulled? `node`/`git` present? |
| 2 | `aisast scan /tmp/aisast-demo --deep` | taint analysis → **AI deep scan** (access control, IDOR, logic) → **AI triage** of every finding → tracking → HTML/JSON/SARIF/MD |
| 3 | `aisast explain <top-id> -Q "How would an attacker exploit this…"` | contextual explanation + follow-up Q&A from the model |
| 4 | `aisast fix … --test-cmd "pytest" --apply --git` | per-function **AI patches** → syntax check → security re-scan → independent AI review → test gate → apply → commit on `aisast/fix-<timestamp>` |
| 5 | `pytest` | functional tests on the fixed code |
| 6 | `aisast verify` | re-scan: fixed findings become `verified` |
| 7 | `aisast status` | remediation status per finding |

## Recorded run (no LLM available)

This output was recorded in the build environment, which had no access to Ollama models, so the AI
steps were skipped automatically and remediation used the deterministic templates. With Ollama
running you additionally get triage verdicts/explanations, deep-scan findings (`[AI-found]`), an
executive summary, Q&A, LLM-written patches for the regions templates cannot fix, and an AI
review badge on every patch.

```text
━━ 0. Prepare a fresh copy of the vulnerable app in /tmp/aisast-demo (git repo)
functional tests: PASS on vulnerable code

━━ 2. Scan
[1/5] Static analysis: 12 files
      37 findings from the deterministic engine in 0.039s
...
SEVERITY   RISK  ID           TITLE                              LOCATION
CRITICAL    9.8  AIS-DC9F2BF7 SQL Injection                      app/db.py:36
CRITICAL    9.8  AIS-9C7691DF SQL Injection                      app/main.py:83
CRITICAL    9.8  AIS-86530E97 Server-Side Template Injection     app/main.py:124
...
Findings: 37  (critical: 12, high: 16, medium: 8, low: 1)

━━ 4. Remediate
Generating fixes for 36 findings in 36 code regions (templates (offline))
  ✔ [4/36] app/db.py:33-37 PY-SQLI-TAINT — validated (template, 1 attempt)
  · [11/36] app/main.py:140-144 PY-SSRF — unsupported
  ...
Running tests with all patches applied: python3 -m pytest -q tests
  tests failed — isolating the offending patch(es)
  ✘ dropped AIS-89DCB0A4 (app/main.py:193) — tests fail with this patch
  tests passed
Applied patches to 6 files
Committed 6dad608 on branch aisast/fix-20261109-123527
Validated fixes: 30/36 findings

━━ 5. Validate
10 passed

━━ 7. Remediation status
open: 7  fix_proposed: 0  fixed: 0  verified: 30  reopened: 0  false_positive: 0  accepted_risk: 0
```

What this shows:

* **Detection** – 37 of the 44 labelled issues, none of the 24 safe look-alikes. The SQL injection in
  `db.py:36` is reported with its cross-file path: `request.form` in `main.py:62` → `find_user()` call at
  `main.py:64` → query built at `db.py:35` → `execute()` at `db.py:36`.
* **Validation catches bad fixes** – the template for `eval()` (`ast.literal_eval`) compiled and passed the
  security re-scan, but broke the calculator endpoint; the test gate isolated and dropped just that patch.
* **Push-ready output** – patches applied, committed on a branch, PR description written
  (`.aisast/fixes/PR_DESCRIPTION.md`), per-finding patches in `.aisast/fixes/patches/`.
* **Tracking** – after the re-scan, 30 findings are `verified`; 7 remain `open`: the rejected `eval` fix,
  two SSRF (need an allow-list), two password hashes (need a KDF and migration), the JS `eval`, and the
  `.env` credential (needs rotation). These are what the LLM remediation loop is for.
* **Not detected without AI** – the 5 semantic flaws (2 IDOR, missing authorization on
  `DELETE /admin/users/<id>`, mass assignment in `/profile`, negative-amount transfer). These are the
  targets of `--deep`; the model receives the project's `login_required` / `admin_required` helpers as
  context so it can notice their absence.

## Doing it by hand

```bash
cp -r demo/vulnerable-app /tmp/shop && cd /tmp/shop && git init -q && git add -A && git commit -qm init
aisast scan . --deep                                  # open .aisast/reports/aisast-report.html
aisast explain AIS-DC9F2BF7 -Q "Show a payload that bypasses the login"
aisast fix . --test-cmd "python -m pytest -q tests"   # review .aisast/fixes/aisast-fixes.patch
git apply .aisast/fixes/aisast-fixes.patch            # or: aisast fix . --apply --git
aisast verify .
aisast status . --set AIS-03C5DFF8 accepted_risk --note "local dev .env, rotated"
```

## Without a GPU

Pipeline mechanics can be explored with the Ollama test double (canned answers, no security knowledge):

```bash
python tools/mock_ollama.py --port 11500 &
aisast scan /tmp/shop --deep --ollama-url http://127.0.0.1:11500
```
