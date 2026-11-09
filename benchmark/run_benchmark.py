#!/usr/bin/env python3
"""Benchmark AI-SAST against Semgrep.

Two corpora:
  demo   – demo/vulnerable-app with line-level ground truth (vulnerable + safe look-alikes)
  owasp  – OWASP Benchmark for Python (independent, 1,230 labelled test cases)

Usage:
  python benchmark/run_benchmark.py demo  --semgrep-config <rules>
  python benchmark/run_benchmark.py owasp --corpus <BenchmarkPython> --semgrep-config <rules> [--split holdout]
  add --ai [--model qwen2.5-coder:7b] [--deep] to also run the Ollama-powered stages.

Semgrep config: any value accepted by `semgrep --config` (e.g. p/default, p/python, or a local
directory of rules such as a checkout of github.com/semgrep/semgrep-rules).
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aisast.context import region_for  # noqa: E402
from aisast.rules import category_for_cwe  # noqa: E402
from aisast.scanner import language_of  # noqa: E402

# ----------------------------------------------------------------------------- category mapping
SEMGREP_KEYWORDS = [  # first match wins; checked against the rule id
    (r"nosql|mongo", "nosqli"), (r"sql", "sqli"), (r"xpath", "xpathi"), (r"ldap", "ldapi"),
    (r"xxe|xml-?external|lxml|defused|xmlparser|etree", "xxe"),
    (r"render-template-string|ssti|template-injection|jinja", "ssti"),
    (r"pickle|marshal|deserializ|yaml-load|pyyaml|unserialize|shelve|dill", "deserialization"),
    (r"eval|exec-detected|exec-use|code-string|new-function|vm-|compile", "code-injection"),
    (r"subprocess|system-call|child-process|command|shell|spawn|os-system|popen", "cmdi"),
    (r"redirect", "open-redirect"), (r"ssrf|request-forgery", "ssrf"),
    (r"traversal|path-join|non-literal-fs|open-filename|file-path|tainted-filename|send-file|open-inside|path", "path-traversal"),
    (r"md5|sha1|hash|crypt", "weak-crypto"),
    (r"jwt-decode|unverified-jwt|jwt-none|none-alg|jwt.*verify", "jwt"),
    (r"csrf|csurf", "csrf"),
    (r"secret|api-key|apikey|token|password|credential|aws|private-key|hardcoded", "secrets"),
    (r"random", "insecure-random"), (r"cert|tls|ssl|verify", "tls"), (r"debug", "debug"),
    (r"tempfile|mktemp", "insecure-temp"), (r"csrf|csurf", "csrf"), (r"cookie", "cookie"),
    (r"session", "trust-boundary"),
    (r"prototype|merge", "prototype-pollution"),
    (r"xss|html|innerhtml|document-method|response-write|format-string|template-string|unescaped|markup|mustache|handlebars|send", "xss"),
]
OWASP_MAP = {"pathtraver": "path-traversal", "sqli": "sqli", "cmdi": "cmdi", "codeinj": "code-injection",
             "deserialization": "deserialization", "hash": "weak-crypto", "weakrand": "insecure-random",
             "xss": "xss", "redirect": "open-redirect", "xxe": "xxe", "ldapi": "ldapi", "xpathi": "xpathi",
             "securecookie": "cookie", "trustbound": "trust-boundary"}


def semgrep_category(r: dict) -> str:
    rid = r["check_id"].split(".")[-1].lower()
    for rx, cat in SEMGREP_KEYWORDS:
        if re.search(rx, rid):
            return cat
    cwes = r["extra"].get("metadata", {}).get("cwe", [])
    cwes = cwes if isinstance(cwes, list) else [cwes]
    for c in cwes:
        m = re.match(r"(CWE-\d+)", str(c))
        if m:
            cat = category_for_cwe(m.group(1))
            if cat != "other":
                return cat
    return "other"


# ----------------------------------------------------------------------------- tool runners
def run_semgrep(target: Path, config: str, extra: list[str] | None = None) -> tuple[list[dict], float, dict]:
    t0 = time.time()
    cmd = ["semgrep", "scan", "--config", config, "--json", "--dataflow-traces", "--metrics=off",
           "--disable-version-check", "--no-git-ignore", "-q", "--timeout", "30", *(extra or []), str(target)]
    p = subprocess.run(cmd, capture_output=True, text=True)
    secs = time.time() - t0
    data = json.loads(p.stdout or "{}")
    out = []
    for r in data.get("results", []):
        meta = r["extra"].get("metadata", {})
        if meta.get("category", "security") != "security":
            continue  # only security rules (exclude best-practice / correctness / performance)
        out.append({"tool": "semgrep", "rule": r["check_id"].split(".")[-1], "file": r["path"].replace(str(target) + "/", ""),
                    "line": r["start"]["line"], "category": semgrep_category(r),
                    "has_fix": bool(r["extra"].get("fix")), "has_trace": bool(r["extra"].get("dataflow_trace")),
                    "has_cwe": bool(meta.get("cwe")), "severity": r["extra"].get("severity", ""),
                    "message_len": len(r["extra"].get("message", ""))})
    ver = subprocess.run(["semgrep", "--version"], capture_output=True, text=True).stdout.strip()
    return out, secs, {"version": ver, "errors": len(data.get("errors", [])), "config": config}


def run_aisast(target: Path, strict: bool = False, ai: bool = False, model: str = "", deep: bool = False,
               ollama_url: str = "") -> tuple[list[dict], float, dict]:
    with tempfile.TemporaryDirectory() as out:
        cmd = [sys.executable, "-m", "aisast", "scan", str(target), "--format", "json", "--out", out, "-q", "--no-cache"]
        if not ai:
            cmd.append("--no-ai")
        if strict:
            cmd.append("--strict")
        if deep:
            cmd.append("--deep")
        if model:
            cmd += ["--model", model]
        if ollama_url:
            cmd += ["--ollama-url", ollama_url]
        t0 = time.time()
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)
        secs = time.time() - t0
        data = json.loads((Path(out) / "aisast-report.json").read_text())
    shutil.rmtree(target / ".aisast", ignore_errors=True)
    out_f = []
    for f in data["findings"]:
        out_f.append({"tool": "aisast", "rule": f["rule_id"], "file": f["file"], "line": f["line"], "category": f["category"],
                      "has_fix": False, "has_trace": bool(f["trace"]), "has_cwe": bool(f["cwe"]), "severity": f["severity"],
                      "engine": f["engine"], "confidence": f["confidence"], "ai_verdict": f.get("ai", {}).get("verdict")})
    info = {"ai_enabled": data["ai"].get("enabled", False), "model": data["ai"].get("model"),
            "suppressed": len(data.get("suppressed", [])), "llm_stats": data["ai"].get("llm_stats", {})}
    if p.returncode not in (0, 2):
        info["stderr"] = p.stderr[-500:]
    return out_f, secs, info


# ----------------------------------------------------------------------------- demo corpus scoring
def resolve_gt(corpus: Path, gt: dict) -> list[dict]:
    entries = []
    for e in gt["entries"]:
        locs = []
        for f, anchor in [(e["file"], e["anchor"])] + [tuple(x) for x in e.get("also", [])]:
            lines = (corpus / f).read_text().splitlines()
            hits = [i + 1 for i, l in enumerate(lines) if anchor in l]
            if len(hits) != 1:
                raise SystemExit(f"ground truth anchor for {e['id']} matched {len(hits)} lines: {anchor!r}")
            src = (corpus / f).read_text()
            lang = language_of(Path(f))
            reg = region_for(src, hits[0], lang) if lang not in ("config", "") else None
            locs.append({"file": f, "line": hits[0], "region": (reg.start, reg.end) if reg and reg.kind == "function" else (hits[0], hits[0])})
        entries.append({**e, "locs": locs})
    return entries


def compatible(a: str, b: str, groups: list[list[str]]) -> bool:
    if a == b:
        return True
    return any(a in g and b in g for g in groups)


def score_demo(findings: list[dict], entries: list[dict], groups) -> dict:
    # dedupe: one finding per (file, line, category) per tool
    uniq = {(f["file"], f["line"], f["category"]): f for f in findings}
    matched_entries, labels = defaultdict(list), {}
    unlabeled = []
    for key, f in uniq.items():
        best = None
        for e in entries:
            if not compatible(f["category"], e["category"], groups):
                continue
            for loc in e["locs"]:
                if loc["file"] != f["file"]:
                    continue
                lo, hi = loc["region"]
                if lo <= f["line"] <= hi or abs(f["line"] - loc["line"]) <= 1:
                    dist = abs(f["line"] - loc["line"])
                    if best is None or dist < best[1]:
                        best = (e, dist)
        if best:
            matched_entries[best[0]["id"]].append(f)
            labels[key] = best[0]["id"]
        else:
            unlabeled.append(f)
    counted = [e for e in entries if e.get("counted", True)]
    vuln = [e for e in counted if e["vulnerable"]]
    safe = [e for e in counted if not e["vulnerable"]]
    tp = [e for e in vuln if e["id"] in matched_entries]
    fn = [e for e in vuln if e["id"] not in matched_entries]
    fp_decoy = [e for e in safe if e["id"] in matched_entries]
    fp = len(fp_decoy) + len(unlabeled)
    prec = len(tp) / (len(tp) + fp) if tp or fp else 0
    rec = len(tp) / len(vuln) if vuln else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    non_ai = [e for e in vuln if not e.get("ai_only")]
    tp_findings = [f for k, f in uniq.items() if k in labels and next(e for e in entries if e["id"] == labels[k])["vulnerable"]]
    return {
        "tp": len(tp), "fn": len(fn), "fp_on_safe_lookalikes": len(fp_decoy), "fp_unlabeled": len(unlabeled), "fp": fp,
        "precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3),
        "recall_rule_detectable": round(sum(1 for e in tp if not e.get("ai_only")) / len(non_ai), 3),
        "ai_only_detected": f"{sum(1 for e in tp if e.get('ai_only'))}/{sum(1 for e in vuln if e.get('ai_only'))}",
        "interprocedural_detected": f"{sum(1 for e in tp if e.get('interprocedural'))}/{sum(1 for e in vuln if e.get('interprocedural'))}",
        "safe_lookalikes_flagged": f"{len(fp_decoy)}/{len(safe)}",
        "raw_findings": len(findings), "unique_findings": len(uniq),
        "tp_with_trace": f"{sum(1 for f in tp_findings if f['has_trace'])}/{len(tp_findings)}",
        "missed": [e["id"] for e in fn], "fp_ids": [e["id"] for e in fp_decoy],
        "unlabeled": [f"{f['file']}:{f['line']} {f['rule']} ({f['category']})" for f in unlabeled],
        "tp_ids": [e["id"] for e in tp],
    }


# ----------------------------------------------------------------------------- remediation comparison (demo)
def py_js_syntax_ok(root: Path) -> tuple[bool, list[str]]:
    bad = []
    for p in root.rglob("*.py"):
        if ".aisast" in p.parts:
            continue
        try:
            compile(p.read_text(), str(p), "exec")
        except SyntaxError as e:
            bad.append(f"{p.relative_to(root)}: {e.msg}")
    if shutil.which("node"):
        for p in root.rglob("*.js"):
            r = subprocess.run(["node", "--check", str(p)], capture_output=True, text=True)
            if r.returncode:
                bad.append(f"{p.relative_to(root)}: node --check failed")
    return not bad, bad


def run_tests(root: Path) -> bool:
    r = subprocess.run([sys.executable, "-m", "pytest", "-q", "tests", "-p", "no:cacheprovider"], cwd=root, capture_output=True, text=True)
    shutil.rmtree(root / "app" / "uploads", ignore_errors=True)
    return r.returncode == 0


def remediation(corpus: Path, gt: dict, semgrep_config: str, ai: bool, model: str, ollama_url: str) -> dict:
    out = {}
    entries = resolve_gt(corpus, gt)
    groups = gt.get("categories_compatible", [])
    # --- Semgrep autofix
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "c"
        shutil.copytree(corpus, work, ignore=shutil.ignore_patterns(".aisast", "__pycache__"))
        before, _, _ = run_semgrep(work, semgrep_config)
        sb = score_demo(before, entries, groups)
        tp_keys_with_fix = sum(1 for f in before if f["has_fix"])
        subprocess.run(["semgrep", "scan", "--config", semgrep_config, "--autofix", "--metrics=off", "--disable-version-check", "-q", str(work)],
                       capture_output=True, text=True)
        syn_ok, syn_bad = py_js_syntax_ok(work)
        tests_ok = run_tests(work)
        resolved = gt_resolved(corpus, work, entries)
        out["semgrep"] = {"findings_with_autofix": tp_keys_with_fix, "true_positives": sb["tp"],
                          "gt_vulns_changed_by_fixes": len(resolved), "resolved_ids": resolved,
                          "syntax_ok": syn_ok, "tests_pass": tests_ok, "syntax_errors": syn_bad[:5]}
    # --- AI-SAST fix (templates offline, LLM when --ai)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "c"
        shutil.copytree(corpus, work, ignore=shutil.ignore_patterns(".aisast", "__pycache__"))
        base = [sys.executable, "-m", "aisast"]
        flags = (["--model", model] if model else []) + (["--ollama-url", ollama_url] if ollama_url else []) + ([] if ai else ["--no-ai"])
        subprocess.run(base + ["scan", str(work), "-q", "--format", "json"] + flags, cwd=ROOT, capture_output=True, text=True)
        t0 = time.time()
        subprocess.run(base + ["fix", str(work), "-q", "--apply", "--test-cmd", f"{sys.executable} -m pytest -q tests -p no:cacheprovider"] + flags,
                       cwd=ROOT, capture_output=True, text=True)
        fix_secs = time.time() - t0
        last = json.loads((work / ".aisast" / "last-scan.json").read_text())
        validated = sum(1 for f in last["findings"] if f.get("fix", {}).get("status") == "validated")
        shutil.rmtree(work / ".aisast", ignore_errors=True)
        syn_ok, syn_bad = py_js_syntax_ok(work)
        tests_ok = run_tests(work)
        resolved = gt_resolved(corpus, work, entries)
        after_sg, _, _ = run_semgrep(work, semgrep_config)
        out["aisast"] = {"findings_with_validated_fix": validated, "gt_vulns_changed_by_fixes": len(resolved),
                         "resolved_ids": resolved, "syntax_ok": syn_ok, "tests_pass": tests_ok, "syntax_errors": syn_bad[:5],
                         "fix_seconds": round(fix_secs, 1), "mode": "llm+templates" if ai else "templates (offline)",
                         "semgrep_findings_after_aisast_fixes": len({(f['file'], f['line'], f['category']) for f in after_sg})}
    return out


def gt_resolved(orig: Path, fixed: Path, entries: list[dict]) -> list[str]:
    """A ground-truth vulnerability counts as remediated when its vulnerable line was changed
    by the fix AND an independent re-scan by BOTH tools no longer reports that category nearby."""
    a_find, _, _ = run_aisast(fixed)
    s_find, _, _ = run_semgrep(fixed, ARGS.semgrep_config)
    allf = a_find + s_find
    res = []
    for e in entries:
        if not e["vulnerable"] or not e.get("counted", True):
            continue
        loc = e["locs"][0]
        new_text = (fixed / loc["file"]).read_text().splitlines()
        if any(e["anchor"] in l for l in new_text):
            continue  # untouched
        # find where the function now lives: nearest line similar to the old region start
        still = [f for f in allf if f["file"] == loc["file"] and compatible(f["category"], e["category"], [])
                 and abs(f["line"] - loc["line"]) <= (loc["region"][1] - loc["region"][0]) + 6]
        if not still:
            res.append(e["id"])
    return res


# ----------------------------------------------------------------------------- OWASP Benchmark scoring
def owasp_expected(corpus: Path, split: str) -> dict[str, dict]:
    exp = {}
    with open(next(corpus.glob("expectedresults-*.csv"))) as fh:
        for row in csv.reader(fh):
            if not row or row[0].startswith("#"):
                continue
            name, cat, real, cwe = row[0], row[1], row[2] == "true", row[3]
            num = int(name[-5:])
            if split == "dev" and num % 2 == 0 or split == "holdout" and num % 2 == 1:
                continue
            exp[name] = {"category": OWASP_MAP[cat], "owasp_category": cat, "real": real, "cwe": cwe}
    return exp


def score_owasp(findings: list[dict], expected: dict) -> dict:
    flagged = defaultdict(set)
    for f in findings:
        m = re.search(r"(BenchmarkTest\d{5})", f["file"])
        if m:
            flagged[m.group(1)].add(f["category"])
    per = defaultdict(Counter)
    for name, e in expected.items():
        hit = e["category"] in flagged.get(name, set())
        key = ("tp" if hit else "fn") if e["real"] else ("fp" if hit else "tn")
        per[e["owasp_category"]][key] += 1
    rows, tot = {}, Counter()
    for cat, c in sorted(per.items()):
        tpr = c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else 0
        fpr = c["fp"] / (c["fp"] + c["tn"]) if c["fp"] + c["tn"] else 0
        rows[cat] = {**c, "tpr": round(tpr, 3), "fpr": round(fpr, 3), "score": round(tpr - fpr, 3)}
        tot.update(c)
    tpr = tot["tp"] / (tot["tp"] + tot["fn"])
    fpr = tot["fp"] / (tot["fp"] + tot["tn"])
    prec = tot["tp"] / (tot["tp"] + tot["fp"]) if tot["tp"] + tot["fp"] else 0
    avg = lambda k: round(sum(r[k] for r in rows.values()) / len(rows), 3)  # noqa: E731
    return {"categories": rows, "overall": {**tot, "tpr": round(tpr, 3), "fpr": round(fpr, 3), "precision": round(prec, 3),
                                            "youden": round(tpr - fpr, 3), "avg_category_score": avg("score"),
                                            "avg_tpr": avg("tpr"), "avg_fpr": avg("fpr")}}


# ----------------------------------------------------------------------------- main
def main():
    global ARGS
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus_kind", choices=["demo", "owasp"])
    ap.add_argument("--corpus", default=str(ROOT / "demo" / "vulnerable-app"))
    ap.add_argument("--semgrep-config", required=True)
    ap.add_argument("--split", choices=["all", "dev", "holdout"], default="all")
    ap.add_argument("--ai", action="store_true", help="also run AI-SAST with Ollama")
    ap.add_argument("--deep", action="store_true")
    ap.add_argument("--model", default="")
    ap.add_argument("--ollama-url", default="")
    ap.add_argument("--strict", action="store_true", help="run AI-SAST with --strict")
    ap.add_argument("--skip-fix", action="store_true")
    ap.add_argument("--out", default=str(ROOT / "benchmark" / "results"))
    ARGS = ap.parse_args()
    corpus = Path(ARGS.corpus).resolve()
    out_dir = Path(ARGS.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    results = {"corpus": ARGS.corpus_kind, "split": ARGS.split, "date": time.strftime("%Y-%m-%d %H:%M"), "tools": {}}

    sg, sg_t, sg_info = run_semgrep(corpus, ARGS.semgrep_config)
    runs = {"semgrep": (sg, sg_t, sg_info)}
    a, a_t, a_info = run_aisast(corpus, strict=ARGS.strict)
    runs["aisast-static"] = (a, a_t, a_info)
    if ARGS.ai:
        ai, ai_t, ai_info = run_aisast(corpus, strict=ARGS.strict, ai=True, model=ARGS.model, deep=ARGS.deep, ollama_url=ARGS.ollama_url)
        runs["aisast-ai"] = (ai, ai_t, ai_info)

    if ARGS.corpus_kind == "demo":
        gt = json.loads((corpus / "ground_truth.json").read_text())
        entries = resolve_gt(corpus, gt)
        for name, (fs, secs, info) in runs.items():
            results["tools"][name] = {"seconds": round(secs, 2), "info": info, **score_demo(fs, entries, gt.get("categories_compatible", []))}
        if not ARGS.skip_fix:
            results["remediation"] = remediation(corpus, gt, ARGS.semgrep_config, ARGS.ai, ARGS.model, ARGS.ollama_url)
    else:
        splits = ["dev", "holdout", "all"] if ARGS.split == "all" else [ARGS.split]
        for name, (fs, secs, info) in runs.items():
            results["tools"][name] = {"seconds": round(secs, 2), "info": info}
            for sp in splits:
                expected = owasp_expected(corpus, sp)
                results["tools"][name][sp] = {"test_cases": len(expected), **score_owasp(fs, expected)}
        (out_dir / f"owasp-raw-findings{'-ai' if ARGS.ai else ''}.json").write_text(json.dumps({k: v[0] for k, v in runs.items()}))
    name = f"{ARGS.corpus_kind}-{ARGS.split}{'-ai' if ARGS.ai else ''}{'-strict' if ARGS.strict else ''}.json"
    (out_dir / name).write_text(json.dumps(results, indent=2))
    def brief(v):
        if "dev" in v or "holdout" in v:
            return {sp: v[sp]["overall"] for sp in ("dev", "holdout", "all") if sp in v} | {"seconds": v["seconds"]}
        return {kk: vv for kk, vv in v.items() if kk not in ("categories", "unlabeled", "info")}
    print(json.dumps({k: brief(v) for k, v in results["tools"].items()}, indent=1))
    if "remediation" in results:
        print(json.dumps(results["remediation"], indent=1))
    print(f"\nwritten {out_dir / name}")


if __name__ == "__main__":
    main()
