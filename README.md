# AI-SAST

**AI-powered static application security testing that runs entirely on your machine.**
A taint-tracking SAST engine for Python and JavaScript/TypeScript, combined with a local LLM
(via [Ollama](https://ollama.com)) that verifies and explains findings, discovers flaws rules
cannot express (broken access control, IDOR, business logic), and writes **validated,
push-ready fixes**. Your source code never leaves the machine: the only network traffic is to
the Ollama server you point it at (default `http://localhost:11434`).

```
 ┌────────────┐   ┌───────────────────────────┐   ┌─────────────────────────────┐   ┌───────────────┐
 │ source tree │──▶│ 1. deterministic engine   │──▶│ 2. LLM stages (Ollama)       │──▶│ 4. reports     │
 └────────────┘   │  • Python AST taint flow  │   │  • triage: verify + explain  │   │ HTML · JSON    │
                  │    (inter-file summaries,│   │  • deep scan: access control,│   │ SARIF · MD     │
                  │    sanitizers, guards)    │   │    IDOR, logic (grounded)    │   │ + tracking     │
                  │  • JS/TS flow-lite        │   │  • executive summary         │   └───────────────┘
                  │  • secrets (any file)     │   └──────────────┬──────────────┘
                  └───────────────────────────┘                  ▼
                                    ┌──────────────────────────────────────────────────────┐
                                    │ 3. remediation: LLM patch → syntax check → security   │
                                    │    re-scan → independent AI review → project tests    │
                                    │    (feedback loop on failure, template fallback)      │
                                    │    → unified diffs, fixed files, git branch + commit  │
                                    └──────────────────────────────────────────────────────┘
```

## Highlights

| | |
|---|---|
| **Detection** | Flow-sensitive taint analysis with inter-procedural, cross-file function summaries; category-aware sanitizers; constant folding; path-sensitive joins; field-sensitive dicts/ConfigParser/lists; recognition of validation guards. 47 rules in 24 vulnerability categories plus secret scanning; the AI deep scan adds access-control and logic categories. |
| **AI triage** | Every finding is checked by the model against the real code and data-flow trace; it returns a verdict, explanation, exploit scenario and fix guidance. Guardrails: severity can move at most one level; suppression needs ≥ 0.75 confidence (≥ 0.85 for critical); suppressed items stay in the report for audit. |
| **AI deep scan** (`--deep`) | The model audits each file with the project's auth helpers as context and reports what rules miss (missing authorization, IDOR, mass assignment, business-logic abuse). Every candidate must quote code that actually exists at the reported line, or it is discarded. |
| **AI remediation** | Fixes are generated per function, then must pass syntax checking, a security re-scan, an independent AI review and (optionally) your test suite. Failures are fed back to the model (up to 3 rounds). Output: per-finding patches, a combined `git apply`-able patch, fixed files, a PR description, and optionally a commit on a new branch. |
| **Offline mode** | Without Ollama the deterministic engine and 30+ fix templates still work (`--no-ai`). |
| **Tracking** | Stable fingerprints survive code moves. Status lifecycle `open → fix_proposed → fixed → verified`, plus `reopened`, `false_positive`, `accepted_risk`, with history. |
| **Reports** | Self-contained HTML (filterable, code context, data-flow, AI analysis, diffs), JSON, SARIF 2.1.0 (GitHub code scanning, with codeFlows and fixes), Markdown. |
| **Zero dependencies** | Python ≥ 3.11 standard library only. |

## Install

```bash
# 1. Ollama (https://ollama.com/download), then pull a code model
ollama pull qwen2.5-coder:7b          # default; any instruction-tuned code model works
# optional, better fixes on bigger hardware:
ollama pull qwen2.5-coder:14b

# 2. AI-SAST
cd aisast
python3 -m pip install .              # or: pip install -e ".[dev]"
aisast doctor                         # checks Ollama, model, node (JS validation), git
```

No install? `python3 -m aisast ...` works from the repository root.

## Quick start

```bash
aisast scan path/to/project                 # rules + AI triage, reports in path/to/project/.aisast/reports/
aisast scan path/to/project --deep          # + AI deep scan for access-control & logic flaws
aisast fix  path/to/project                 # validated patches for the last scan
aisast fix  path/to/project --test-cmd "pytest -q" --apply --git   # test-gated, applied, committed on a branch
aisast verify path/to/project               # re-scan; fixed findings become "verified"
```

Open `.aisast/reports/aisast-report.html` in a browser.

### Commands

| command | purpose |
|---|---|
| `aisast scan PATH [--deep] [--no-ai] [--strict] [--fail-on high] [--format html,json,sarif,md] [--out DIR]` | Scan. `--fail-on` makes the exit code 2 when a finding at/above that severity exists (CI gate). |
| `aisast fix PATH [--ids ID ...] [--apply] [--git] [--test-cmd CMD] [--no-review] [--attempts N]` | Generate and validate fixes for the last scan. |
| `aisast verify PATH` | Re-scan and update remediation status. |
| `aisast status PATH [--set ID STATUS --note TEXT] [--filter STATUS]` | Show or change status (e.g. mark `accepted_risk`). |
| `aisast explain ID [-p PATH] [-Q "question"]` | Show the AI analysis for a finding; ask a follow-up question. |
| `aisast report PATH [--format ...]` | Re-render reports from the last scan. |
| `aisast doctor` · `aisast rules` | Environment check · list rules. |

Common flags: `--model`, `--fix-model`, `--ollama-url`, `--no-ai`, `--no-cache`, `--config FILE`, `-q`.

Suppress a single line with a trailing `# aisast: ignore` (or `// aisast-ignore`, `# nosec`).

## Configuration

Optional `aisast.toml` in the scanned project (see `aisast.toml.example`). Environment overrides:
`OLLAMA_HOST`, `AISAST_MODEL`, `AISAST_FIX_MODEL`.

## CI (GitHub Actions example)

```yaml
- run: pip install ./aisast
- run: aisast scan . --no-ai --format sarif --out reports --fail-on high   # fast deterministic gate
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with: { sarif_file: reports/aisast-report.sarif }
```
Run the AI stages on a self-hosted runner that has Ollama.

## Demo

`demo/` contains a deliberately vulnerable Flask + Express application with labelled ground truth
and functional tests. See **[docs/DEMO.md](docs/DEMO.md)** or run `./demo/run_demo.sh`.

## Benchmark

On the independent **OWASP Benchmark for Python** (1,230 labelled cases, held-out half), AI-SAST's
deterministic engine alone reached TPR 0.88 / FPR 0.05 (Youden 0.83) versus Semgrep CE with 735
community rules at TPR 0.32 / FPR 0.14 (Youden 0.19), about 20× faster. Full methodology, the
demo-corpus comparison, remediation results and caveats: **[docs/BENCHMARK.md](docs/BENCHMARK.md)**.

## How the AI is used safely

* **Local only** – prompts go to your Ollama server; nothing else is contacted. Responses are cached in `.aisast/cache`.
* **Grounded** – the model sees the exact code region, imports and data-flow trace; deep-scan claims must quote real code.
* **Bounded authority** – AI can confirm, explain, re-rank (±1 severity) and suppress with high confidence; it cannot invent rule findings or silently drop critical ones.
* **Verified fixes** – no patch is marked ready unless it compiles, the scanner no longer sees the issue, an independent review approves it and (when configured) tests pass.

## Limitations

* Deepest analysis is for Python; JS/TS uses a lighter flow analysis. Other languages are covered by the AI deep scan and secret scanning only.
* LLM output quality depends on the model you run; 7B models are good at triage/explanations, larger models write better fixes. Always review patches before merging.
* Static analysis cannot see runtime configuration; some reported issues may be mitigated elsewhere (use `status --set ID accepted_risk`).

## Project layout

```
aisast/            package (analyzers/, llm/, report/, remediate.py, templates.py, tracking.py, cli.py)
demo/              vulnerable sample app, ground truth, demo script
benchmark/         benchmark harness and stored results
docs/              DEMO.md, BENCHMARK.md, ARCHITECTURE.md
tests/             pytest suite (uses tools/mock_ollama.py as an Ollama test double)
tools/             mock_ollama.py
```

Run the tests: `python3 -m pytest -q tests`.
