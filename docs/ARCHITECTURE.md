# Architecture

```
aisast/
├── cli.py              argparse CLI (scan, fix, verify, status, explain, report, doctor, rules)
├── pipeline.py         end-to-end workflows used by the CLI and the benchmark harness
├── config.py           defaults ← aisast.toml ← environment ← flags
├── models.py           Finding / ScanResult, severities, fingerprints, risk score
├── rules.py            rule catalog → category, CWE, OWASP Top 10, default severity, guidance
├── scanner.py          file discovery, analyzer dispatch, suppression comments, dedupe, scoring
├── analyzers/
│   ├── python_taint.py AST taint engine (details below)
│   ├── javascript.py   JS/TS flow-lite analyzer
│   └── secrets.py      provider token formats + entropy-checked generic credentials
├── context.py          enclosing function/statement regions, numbered snippets, auth-helper context
├── llm/
│   ├── ollama.py       stdlib HTTP client: /api/chat with JSON-schema output, retries, repair, cache
│   ├── prompts.py      prompts + JSON schemas for triage, deep scan, fix, review, summary, Q&A
│   └── analysis.py     triage (+guardrails), deep scan (+grounding), executive summary, Q&A
├── remediate.py        fix planning, generation loop, validation gates, patch/branch output
├── templates.py        deterministic fix templates (offline mode and LLM fallback)
├── tracking.py         .aisast/state.json lifecycle across scans
└── report/             html.py (self-contained), formats.py (JSON, SARIF 2.1.0, Markdown)
```

## 1. Deterministic engine

### Python taint analysis (`analyzers/python_taint.py`)
* **Sources**: Flask/Django/FastAPI request objects (`request.args/form/json/cookies/headers/...`), route path
  parameters, `input()`, `sys.argv` (local, lower confidence).
* **State per variable**: taint origins (each with a trace), a *safe* flag, and a constant value when known.
* **Control flow**: path-sensitive joins for `if/else`, loops (two iterations + `break`/`continue` exits),
  `try/except/finally`, `match` (constant subjects resolve to one case). Conditions that fold to constants
  only analyse the taken branch. Paths that `return`/`raise` are dropped from joins.
* **Precision features**: category-specific sanitizers (e.g. `html.escape` clears XSS but not SQLi; `int()`
  clears everything); field-sensitive dicts and ConfigParser (`d["k"]`, `conf.set/get`); element-precise lists
  (`append/insert/pop` then `lst[i]`); validation guards (`if '../' in p: return`, `if x not in ALLOWED: abort()`,
  `if not url.startswith('/'): url = '/'`, guards on `urlparse(x)` results); allow-list conditional expressions.
* **Inter-procedural**: every function gets a summary — which parameters reach which sinks, and which reach
  the return value (with the sanitization applied). Summaries are computed to a fixpoint and resolved across
  files through imports, so a flow from `routes.py` into `db.py` is reported at the real sink with the full trace.
* **Sinks**: SQL, OS command (incl. `sh -c` argument lists), code eval, pickle/YAML/marshal, path operations,
  SSRF, open redirect, SSTI, XSS (returned HTML, response helpers), XXE (SAX/minidom/lxml with external
  entities), XPath, LDAP, session trust boundary.
* **Pattern rules**: weak hashes and PRNG in security contexts (`--strict`: everywhere), TLS verification off,
  JWT without verification, debug mode, insecure cookies, CSRF disabled, `mktemp`, hardcoded secrets.
  Pattern findings on values of unknown provenance are emitted with *low* confidence for AI triage.

### JavaScript / TypeScript (`analyzers/javascript.py`)
Dependency-free: string-aware comment stripping, ordered assignment tracking (incl. destructuring) from
`req.*`/`location.*`/`process.argv`, sanitizer stripping inside expressions, balanced-parenthesis sink
argument extraction (multi-line calls). Sinks: SQL, NoSQL operator injection, `exec/spawn`, `eval/Function`,
reflected and DOM XSS, path traversal, SSRF, open redirect, `node-serialize`, prototype pollution,
`Math.random` tokens, MD5/SHA-1 passwords, `jwt.decode`, TLS verification off.

### Scoring
`risk = base(severity) × confidence factor (+0.5 proven remote taint, +0.3 reachable from a route)`,
bucketed into P1–P4. Fingerprints hash rule + file + function + normalised code line, so they survive edits
elsewhere in the file.

## 2. LLM stages (Ollama)

| stage | input | output | guardrails |
|---|---|---|---|
| **Triage** | enclosing function (numbered, sink marked), data-flow trace, module imports | verdict, confidence, severity, explanation, exploit scenario, root cause, remediation | severity moves ≤ 1 level; suppression needs ≥ 0.75 (≥ 0.85 for critical); suppressed findings kept in report |
| **Deep scan** | file chunks cut at top-level boundaries, project auth helpers, list of already-known findings | new findings (category enum, CWE, line, verbatim evidence) | evidence must match real code near the line (line is snapped to it) or the finding is dropped; confidence ≥ 0.6; dedupe; then triaged like any other finding |
| **Fix** | the whole enclosing function(s), all findings in it, triage guidance, module header, validator feedback | replacement code, new imports, summary, changes, risk | see validation gates |
| **Review** | original vs patched region | fixes? preserves behaviour? new issues? | a "no" sends feedback for another attempt |
| **Summary / Q&A** | top findings + stats / one finding | executive summary, actions / answer | — |

All calls use Ollama's structured outputs (JSON schema in `format`) with fallback to JSON mode, JSON repair
and one corrective retry. Responses are cached by a hash of (model, prompt, schema) under `.aisast/cache`,
making re-scans fast and deterministic (`--no-cache` to disable). Temperature defaults to 0.1 with a fixed seed.

## 3. Remediation pipeline (`remediate.py`)

1. **Plan**: group findings by enclosing function so one coherent patch fixes everything in that region.
2. **Generate**: LLM (up to `fix_attempts`, temperature raised after the first try), else template.
3. **Validate** each candidate: (a) `compile()` / `node --check`; (b) in-memory re-scan of the whole project
   with the patched file — the issue must be gone from the region and no new medium+ finding may appear
   anywhere in the file; (c) independent AI review; failures produce targeted feedback for the next attempt.
4. **Combine** validated region patches per file bottom-up, add imports once.
5. **Test** (optional `--test-cmd`): run the suite on a temporary copy with all patches; on failure, test each
   patch alone and drop the ones that break behaviour.
6. **Emit**: `.aisast/fixes/patches/*.patch`, `aisast-fixes.patch` (`git apply`-able), `files/` (fixed copies),
   `PR_DESCRIPTION.md`; with `--apply` write the tree, with `--git` commit on `aisast/fix-<timestamp>`.

## 4. Tracking (`tracking.py`)

`state.json` maps fingerprint → record with status and history. Each scan: new → `open`; previously
`fixed`/`verified` and seen again → `reopened`; active and no longer seen (file still scanned) → `verified`.
Human decisions (`false_positive`, `accepted_risk`) persist across scans.
