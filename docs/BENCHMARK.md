# Benchmark: AI-SAST vs Semgrep

**Date:** 2026-11-09 · **Raw results:** `benchmark/results/` · **Harness:** `benchmark/run_benchmark.py`

## TL;DR

On the independent **OWASP Benchmark for Python** (held-out half, 615 test cases), AI-SAST's
deterministic engine found **88 %** of real vulnerabilities with a **5 %** false-positive rate
(Youden index **0.83**). Semgrep CE with 735 community security rules found **32 %** at **14 %**
FPR (Youden **0.19**), and took **20× longer**. On the demo application, AI-SAST produced validated,
test-passing fixes that remediated **24 of 44** labelled vulnerabilities offline, versus **2 of 44**
for Semgrep autofix.

The LLM stages (triage, deep scan, LLM-written fixes) were **not** measured here — see
[What was not measured](#what-was-not-measured).

## Setup

| | |
|---|---|
| AI-SAST | 1.0.0, deterministic engine only (`--no-ai`); `--strict` on OWASP (that benchmark counts *every* weak hash/PRNG use as vulnerable) |
| Semgrep | Semgrep CE **1.184.0**; rules = all `python/`, `javascript/` and `generic/secrets/` rule files from `github.com/semgrep/semgrep-rules` @ `16b9e6d` (2026-10-21), **735 files**; flags `--dataflow-traces --timeout 30`. Only results whose rule metadata has `category: security` are scored (this drops best-practice/correctness noise and is slightly favourable to Semgrep). The registry packs (`p/default` etc.) could not be downloaded in the build sandbox; they are curated subsets of the same repository. |
| Machine | 2 vCPU / 7 GB RAM Linux sandbox, Python 3.13 |
| Category mapping | Semgrep rule ids → categories by keyword, falling back to the rule's CWE (`SEMGREP_KEYWORDS` in the harness). Audited: no Semgrep finding in a scored category was lost to mis-mapping. |

## 1. OWASP Benchmark for Python (independent)

[OWASP Benchmark for Python v0.1](https://github.com/OWASP-Benchmark/BenchmarkPython): 1,230 Flask
test cases in 14 CWE categories; 452 are real vulnerabilities and 778 are deliberately safe traps
(constant-folded branches, sanitizers, map/list/ConfigParser shuffles). A test case counts as flagged when
the tool reports a finding of the expected category in that test file. Metrics follow the OWASP
scorecard: TPR, FPR and Youden index (TPR − FPR; 0 = random guessing, 1 = perfect).

**Avoiding overfitting.** After a first baseline run, the engine was improved by inspecting **only the
odd-numbered (dev) test cases**. The even-numbered half was not looked at and is the primary result.
All improvements are general analyses (control-flow joins, list/dict modelling, category-aware
sanitizers, validation guards, LDAP/XPath/XXE/session sinks) — there are no test-specific rules.

### Results

| | TPR | FPR | Precision | Youden | Avg. category score | Time (1,230 files) |
|---|---|---|---|---|---|---|
| **AI-SAST — held-out half** | **0.879** | **0.051** | **0.907** | **0.828** | **0.785** | — |
| AI-SAST — dev half | 0.904 | 0.052 | 0.912 | 0.852 | 0.809 | — |
| AI-SAST — all | 0.892 | 0.051 | 0.910 | 0.840 | 0.796 | **3.9 s** |
| Semgrep — held-out half | 0.323 | 0.135 | 0.576 | 0.188 | 0.161 | — |
| Semgrep — all | 0.321 | 0.136 | 0.578 | 0.185 | 0.157 | 80.7 s |
| *AI-SAST before benchmark-driven improvements (held-out)* | *0.507* | *0.253* | *0.533* | *0.254* | *0.235* | *2.9 s* |

The dev/held-out gap is small (0.852 vs 0.828), which indicates the improvements generalise. Even the
pre-improvement baseline was ahead of Semgrep on Youden (0.254 vs 0.188), but had a higher FPR.

### Per category (held-out half)

| Category | n (vuln/safe) | Semgrep TPR | Semgrep FPR | AI-SAST TPR | AI-SAST FPR |
|---|---|---|---|---|---|
| cmdi | 5/5 | 1.00 | 1.00 | 1.00 | 0.60 |
| codeinj | 10/18 | 1.00 | 1.00 | 1.00 | 0.28 |
| deserialization | 9/20 | 1.00 | 0.35 | 1.00 | 0.25 |
| hash | 34/40 | 0.73 | 0.00 | 1.00 | 0.00 |
| ldapi | 7/7 | 0.00 | 0.00 | 0.86 | 0.00 |
| pathtraver | 28/57 | 0.04 | 0.04 | 0.79 | 0.00 |
| redirect | 10/8 | 0.10 | 0.00 | 0.90 | 0.00 |
| securecookie | 14/5 | 1.00 | 1.00 | 1.00 | 0.00 |
| sqli | 2/4 | 1.00 | 0.00 | 1.00 | 0.00 |
| trustbound | 8/10 | 0.00 | 0.00 | 0.50 | 0.00 |
| weakrand | 48/113 | 0.00 | 0.00 | 1.00 | 0.00 |
| xpathi | 30/65 | 0.00 | 0.00 | 0.63 | 0.09 |
| xss | 13/31 | 0.00 | 0.23 | 0.77 | 0.03 |
| xxe | 5/9 | 1.00 | 1.00 | 0.80 | 0.00 |

Where Semgrep scores 1.00/1.00 its rule matches the sink regardless of data flow (it flags the safe
variants too). AI-SAST's remaining false positives (cmdi, codeinj, deserialization) are mostly cases
where safety depends on runtime string content the static engine does not model — exactly the class
of finding the AI triage stage is designed to review.

## 2. Demo application (line-level ground truth)

`demo/vulnerable-app`: Flask + Express + browser JS, **44 labelled vulnerabilities** and **24 safe
look-alikes** (`ground_truth.json`, located by code anchors). 5 of the vulnerabilities are semantic
(IDOR ×2, missing authorization, mass assignment, business logic) and have no taint/pattern signature.
Findings match a label when the file and category agree and the line is inside the labelled function
(or ±1 line for module-level code). Unmatched findings count as false positives.

> **Bias disclosure:** this corpus was written by the AI-SAST author, so the safe look-alikes reflect
> idioms AI-SAST was built to recognise. Treat it as a demonstration; the OWASP result above is the
> independent evidence.

| | TP | FN | FP (safe look-alikes) | Precision | Recall | F1 | Time |
|---|---|---|---|---|---|---|---|
| **AI-SAST (static)** | **37** | 7 | **0 / 24** | **1.00** | **0.84** | **0.91** | **0.1 s** |
| Semgrep | 29 | 15 | 6 / 24 | 0.83 | 0.66 | 0.73 | 44 s |

* AI-SAST missed: the 5 semantic flaws, a hard-coded fallback JWT secret (`os.environ.get("JWT_SECRET", "dev")`),
  and a session cookie without `HttpOnly`/`Secure` in Express.
* Semgrep missed: path traversal via `send_file`, Python `random` tokens, `SECRET_KEY` literal, NoSQL operator
  injection, axios SSRF, `Math.random` session id, lodash `_.merge` prototype pollution, `mktemp`
  (reported only by a non-security rule), the same cookie, plus 4 of the 5 semantic flaws. Semgrep did
  catch the business-logic case (its `nan-injection` rule fires on `float(request.form[...])`).
* Semgrep false positives: constant table name in an f-string, `IN (?,?,?)` placeholder list, allow-listed
  `ORDER BY`, `escape()`d output, a validated redirect, and a `path.basename`-sanitised file read.

## 3. Remediation

Each tool's automatic fixes were applied to a fresh copy of the demo app, which was then checked by
an **independent oracle**: a labelled vulnerability counts as remediated only if its code line changed
**and neither tool** reports that category in the function afterwards. Syntax and the app's functional
tests (10 tests) were checked after fixing.

| | Findings with an automatic fix | Labelled vulns remediated (oracle) | Syntax OK | Tests pass |
|---|---|---|---|---|
| **AI-SAST** (`fix --test-cmd`, templates only, no LLM) | **30** (validated) | **24 / 44** | ✓ | ✓ |
| Semgrep (`--autofix`) | 4 | 2 / 44 | ✓ | ✓ |

AI-SAST's test gate also caught one template that broke behaviour (`eval` → `ast.literal_eval` broke the
calculator endpoint); it was isolated and dropped automatically, and everything else was committed to a
branch. With an LLM enabled, regions templates cannot fix (SSRF allow-listing, password hashing,
safe expression evaluation, authorization checks) go through the LLM generate → validate → review loop.

## 4. Speed

| corpus | AI-SAST | Semgrep |
|---|---|---|
| OWASP Benchmark (1,230 files) | 3.9 s | 80.7 s |
| Demo app (8 files) | 0.1 s | 44 s |

Semgrep's time is dominated by loading 735 rule files; a smaller rule pack would be faster.
AI-SAST's AI stages add model time on top (seconds per finding on a GPU); the deterministic gate
remains suitable for every commit.

## Areas where AI-SAST is better (measured)

1. **Accuracy on independent code** — Youden 0.83 vs 0.19 on the held-out OWASP half; 2.7× the true-positive
   rate (88 % vs 32 %) with less than half the false-positive rate (5.1 % vs 13.5 %).
2. **False positives on safe look-alikes** — 0 of 24 vs 6 of 24 on the demo; precision 1.00 vs 0.83.
3. **Automated remediation** — 24 vs 2 labelled vulnerabilities remediated with tests passing, from 30 vs 4
   automatic fixes, without any LLM.
4. **Speed** — about 20× faster on the 1,230-file benchmark.

## Where Semgrep is stronger

* **Language breadth and ecosystem** — 30+ languages and thousands of community/pro rules; AI-SAST's deep
  analysis covers Python, a lighter analysis covers JS/TS, and other languages rely on the AI deep scan.
* **Some sinks** — on this OWASP set Semgrep flagged every XXE case (TPR 1.00 vs 0.80, though at FPR 1.00),
  and it caught the NaN-injection logic bug on the demo.
* **Untested here** — Semgrep Pro / AppSec Platform (cross-file taint, more rules) and the registry packs.

## What was not measured

The build sandbox could not download Ollama or model weights, so **no numbers above involve an LLM**.
The AI pipeline itself (transport, schemas, caching, guardrails, grounding of deep-scan claims,
fix feedback loop, review gate) is covered by the test suite against an Ollama test double, which
contains no security knowledge. To measure the AI stages on your hardware:

```bash
ollama pull qwen2.5-coder:7b
python benchmark/run_benchmark.py demo  --semgrep-config p/default --ai --deep --model qwen2.5-coder:7b
python benchmark/run_benchmark.py owasp --corpus /path/to/BenchmarkPython --semgrep-config p/python --strict --ai
```

With `--ai`, the harness adds an `aisast-ai` column (triage suppressions, deep-scan findings, LLM-written
fixes). The quantities to watch are the 5 semantic flaws on the demo (static: 0/5; this is what `--deep`
targets) and the remaining OWASP false positives (what triage targets).

## Reproduce

```bash
git clone --depth 1 https://github.com/semgrep/semgrep-rules /tmp/semgrep-rules     # or use p/default
python benchmark/build_semgrep_ruleset.py /tmp/semgrep-rules /tmp/ruleset
git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkPython /tmp/BenchmarkPython
pip install semgrep pytest flask pyyaml requests pyjwt
python benchmark/run_benchmark.py owasp --corpus /tmp/BenchmarkPython --semgrep-config /tmp/ruleset --strict
python benchmark/run_benchmark.py demo  --semgrep-config /tmp/ruleset
```
