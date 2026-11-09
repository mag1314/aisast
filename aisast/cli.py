"""AI-SAST command line interface."""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from .config import load_config
from .models import SEVERITIES, STATUSES, severity_at_least

COLORS = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[90m"}
RESET, BOLD, DIM, GREEN = "\033[0m", "\033[1m", "\033[2m", "\033[32m"


def color_ok() -> bool:
    return sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def c(text: str, code: str) -> str:
    return f"{code}{text}{RESET}" if color_ok() else text


def banner():
    print(c(f"AI-SAST {__version__}", BOLD) + c("  · local, Ollama-powered static application security testing", DIM))


def common(p: argparse.ArgumentParser, positional: bool = True):
    if positional:
        p.add_argument("path", nargs="?", default=".", help="project directory or file (default: .)")
    else:
        p.add_argument("-p", "--path", default=".", help="project directory (default: .)")
    p.add_argument("--config", help="path to aisast.toml")
    p.add_argument("--model", help="Ollama model (default qwen2.5-coder:7b)")
    p.add_argument("--fix-model", help="Ollama model used for remediation (default: --model)")
    p.add_argument("--ollama-url", help="Ollama base URL (default http://localhost:11434 or $OLLAMA_HOST)")
    p.add_argument("--no-ai", action="store_true", help="deterministic engine only (no LLM calls)")
    p.add_argument("--no-cache", action="store_true", help="do not reuse cached LLM responses")
    p.add_argument("-q", "--quiet", action="store_true")


def build_cfg(args):
    root = Path(args.path).resolve()
    cfg = load_config(root if root.is_dir() else root.parent, args.config)
    for attr, val in (("model", args.model), ("fix_model", args.fix_model), ("ollama_url", args.ollama_url)):
        if val:
            setattr(cfg, attr, val)
    if args.no_ai:
        cfg.ai_enabled = False
    if args.no_cache:
        cfg.cache = False
    return root, cfg


def print_findings(result, limit: int = 60):
    fs = result.findings
    if not fs:
        print(c("No findings.", GREEN))
        return
    print()
    print(f"{'SEVERITY':10} {'RISK':>4}  {'ID':12} {'TITLE':34} LOCATION")
    for f in fs[:limit]:
        sev = c(f"{f.severity.upper():10}", COLORS.get(f.severity, ""))
        tag = ""
        if f.ai.get("verdict"):
            tag = c(f" [AI {f.ai['verdict'].replace('_positive', '').replace('true', 'confirmed')}]", DIM)
        if f.engine == "llm":
            tag += c(" [AI-found]", DIM)
        if f.fix.get("status") == "validated":
            tag += c(" [fix ready]", GREEN)
        print(f"{sev} {f.risk_score:>4}  {f.id:12} {f.title[:34]:34} {f.file}:{f.line}{tag}")
    if len(fs) > limit:
        print(c(f"… {len(fs) - limit} more in the report", DIM))


def print_summary(result):
    sev = Counter(f.severity for f in result.findings)
    parts = [c(f"{s}: {sev.get(s, 0)}", COLORS[s]) for s in SEVERITIES if sev.get(s)]
    print()
    print(BOLD * 0 + f"Findings: {len(result.findings)}  (" + ", ".join(parts) + ")"
          + (f"  · AI-suppressed false positives: {len(result.suppressed)}" if result.suppressed else ""))
    tr = result.tracking or {}
    if tr:
        print(f"Tracking: {tr.get('new', 0)} new, {tr.get('existing', 0)} existing, {tr.get('resolved', 0)} resolved since last scan"
              + (f", {tr.get('reopened')} reopened" if tr.get("reopened") else ""))
    s = (result.ai or {}).get("summary", {})
    if s.get("executive_summary"):
        print()
        print(c("AI summary: ", BOLD) + s["executive_summary"])


def cmd_scan(args) -> int:
    from .pipeline import scan, write_reports
    root, cfg = build_cfg(args)
    if args.deep:
        cfg.deep_scan = True
    if args.no_triage:
        cfg.triage = False
    if args.strict:
        cfg.strict = True
    if args.min_severity:
        cfg.min_severity = args.min_severity
    log = (lambda m: None) if args.quiet else print
    if not args.quiet:
        banner()
    result = scan(root, cfg, log)
    formats = [x.strip() for x in (args.format or ",".join(cfg.formats)).split(",") if x.strip()]
    out = Path(args.out).resolve() if args.out else None
    log("[5/5] Writing reports")
    written = write_reports(root, result, cfg, formats, out)
    if not args.quiet:
        print_findings(result)
        print_summary(result)
        print()
        for w in written:
            print(f"  report: {w}")
        print(c("\nNext: `aisast fix " + args.path + "` to generate validated patches.", DIM))
    if args.fail_on:
        if any(severity_at_least(f.severity, args.fail_on) for f in result.findings):
            return 2
    return 0


def cmd_fix(args) -> int:
    from .pipeline import fix, write_reports
    root, cfg = build_cfg(args)
    if args.attempts:
        cfg.fix_attempts = args.attempts
    if args.min_severity:
        cfg.fix_min_severity = args.min_severity
    log = (lambda m: None) if args.quiet else print
    if not args.quiet:
        banner()
    out = fix(root, cfg, log, ids=args.ids, apply=args.apply, git=args.git, test_cmd=args.test_cmd or "",
              review=not args.no_review, max_groups=args.max or 0)
    written = write_reports(root, out["result"], cfg, cfg.formats)
    print()
    print(f"Validated fixes: {out['validated_findings']}/{out['total_findings']} findings")
    print(f"  combined patch : {out['outputs']['combined_patch']}")
    print(f"  per-fix patches: {Path(out['outputs']['combined_patch']).parent / 'patches'}")
    print(f"  PR description : {out['outputs']['pr_description']}")
    print(f"  report         : {written[0] if written else '-'}")
    if out["applied"]:
        print(f"  applied to     : {len(out['applied'])} files")
    if out["git"].get("ok"):
        print(c(f"  git branch     : {out['git']['branch']} ({out['git']['commit']}) → {out['git']['push']}", GREEN))
    elif out["git"]:
        print(f"  git            : {out['git'].get('error')}")
    if not args.apply:
        print(c(f"\nApply with: git apply {out['outputs']['combined_patch']}   (or re-run with --apply [--git])", DIM))
    return 0


def cmd_verify(args) -> int:
    from .pipeline import scan, write_reports
    root, cfg = build_cfg(args)
    cfg.ai_enabled = not args.no_ai and cfg.ai_enabled
    banner()
    result = scan(root, cfg, print)
    write_reports(root, result, cfg, cfg.formats)
    tr = result.tracking
    print()
    for i in tr.get("resolved_ids", []):
        print(f"  ✔ {i} verified fixed")
    print(c(f"Verified fixed: {tr.get('resolved', 0)}", GREEN) + f"   still open: {len(result.findings)}   reopened: {tr.get('reopened', 0)}")
    return 0


def cmd_report(args) -> int:
    from .pipeline import load_last, write_reports
    root, cfg = build_cfg(args)
    result = load_last(root)
    if result is None:
        print("No scan found. Run `aisast scan` first.")
        return 1
    formats = [x.strip() for x in (args.format or ",".join(cfg.formats)).split(",")]
    for w in write_reports(root, result, cfg, formats, Path(args.out).resolve() if args.out else None):
        print(w)
    return 0


def cmd_status(args) -> int:
    from .tracking import load_state, set_status
    root, cfg = build_cfg(args)
    if args.set:
        ident, status = args.set
        rec = set_status(root, ident, status, args.note or "")
        if not rec:
            print(f"Unknown finding {ident}")
            return 1
        print(f"{rec['id']} -> {status}")
        return 0
    state = load_state(root)
    recs = sorted(state["findings"].values(), key=lambda r: (r.get("status") != "open", -float(r.get("risk_score", 0))))
    counts = Counter(r.get("status") for r in recs)
    print("  ".join(f"{s}: {counts.get(s, 0)}" for s in STATUSES))
    print()
    for r in recs:
        if args.filter and r.get("status") != args.filter:
            continue
        print(f"{r['id']:12} {r.get('status', ''):15} {r.get('severity', ''):9} {r['title'][:36]:36} {r['file']}:{r.get('line', '')}")
    return 0


def cmd_explain(args) -> int:
    from .llm.analysis import ask
    from .pipeline import load_last, make_client
    from .scanner import read_sources
    root, cfg = build_cfg(args)
    result = load_last(root)
    f = next((x for x in (result.findings + result.suppressed if result else []) if x.id == args.id or x.fingerprint == args.id), None)
    if not f:
        print(f"Finding {args.id} not found in the last scan.")
        return 1
    print(c(f"{f.id} {f.title} ({f.cwe}) — {f.file}:{f.line}", BOLD))
    for k in ("explanation", "exploit_scenario", "remediation"):
        if f.ai.get(k):
            print(f"\n{k.replace('_', ' ').title()}: {f.ai[k]}")
    if args.question:
        client = make_client(cfg, root)
        h = client.health()
        if not h["ok"]:
            print(f"Ollama unavailable: {h['message']}")
            return 1
        src = read_sources(root, cfg).get(f.file, "")
        print("\n" + c("Answer: ", BOLD) + ask(f, args.question, src, client))
    return 0


def cmd_doctor(args) -> int:
    from .llm.ollama import OllamaClient
    root, cfg = build_cfg(args)
    banner()
    print(f"Python      : {sys.version.split()[0]}")
    print(f"Ollama URL  : {cfg.ollama_url}")
    h = OllamaClient(cfg.ollama_url, cfg.model, timeout=10).health()
    print(f"Ollama      : {'reachable, version ' + str(h['version']) if h['version'] else 'NOT reachable'}")
    print(f"Models      : {', '.join(h['models']) or '-'}")
    print(f"Scan model  : {cfg.model} — {h['message']}")
    if cfg.fix_model and cfg.fix_model != cfg.model:
        h2 = OllamaClient(cfg.ollama_url, cfg.fix_model, timeout=10).health()
        print(f"Fix model   : {cfg.fix_model} — {h2['message']}")
    import shutil
    print(f"node        : {shutil.which('node') or 'not found (JS syntax validation of fixes disabled)'}")
    print(f"git         : {shutil.which('git') or 'not found (--git disabled)'}")
    return 0 if h["ok"] else 1


def cmd_rules(args) -> int:
    from .rules import all_rules
    for r in all_rules():
        print(f"{r['rule_id']:22} {r['severity']:9} {r['cwe']:9} {r['title']}")
    print("AI-<CATEGORY>          (dynamic)  LLM deep-scan findings, e.g. AI-IDOR, AI-MISSING-AUTH, AI-LOGIC")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="aisast", description="AI-powered SAST running fully locally with Ollama.")
    ap.add_argument("--version", action="version", version=f"aisast {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan code for vulnerabilities")
    common(s)
    s.add_argument("--deep", action="store_true", help="AI deep scan: let the model find issues rules miss (slower)")
    s.add_argument("--no-triage", action="store_true", help="skip AI verification/explanations of findings")
    s.add_argument("--strict", action="store_true", help="report every weak hash / PRNG use, not only security contexts")
    s.add_argument("--format", help="comma list: html,json,sarif,md")
    s.add_argument("--out", help="report output directory (default <path>/.aisast/reports)")
    s.add_argument("--min-severity", choices=SEVERITIES)
    s.add_argument("--fail-on", choices=SEVERITIES, help="exit 2 if any finding is at least this severe (CI gate)")
    s.set_defaults(func=cmd_scan)

    f = sub.add_parser("fix", help="generate validated, ready-to-apply fixes for the last scan")
    common(f)
    f.add_argument("--ids", nargs="*", help="only these finding ids")
    f.add_argument("--apply", action="store_true", help="write the fixes into the working tree")
    f.add_argument("--git", action="store_true", help="with --apply: commit on a new branch (push-ready)")
    f.add_argument("--test-cmd", help="command that must pass with the patches applied, e.g. 'pytest -q'")
    f.add_argument("--no-review", action="store_true", help="skip the independent AI review of each patch")
    f.add_argument("--attempts", type=int, help="LLM attempts per fix (default 3)")
    f.add_argument("--min-severity", choices=SEVERITIES)
    f.add_argument("--max", type=int, help="maximum number of code regions to fix")
    f.set_defaults(func=cmd_fix)

    v = sub.add_parser("verify", help="re-scan and mark fixed findings as verified")
    common(v)
    v.set_defaults(func=cmd_verify)

    r = sub.add_parser("report", help="re-render reports from the last scan")
    common(r)
    r.add_argument("--format")
    r.add_argument("--out")
    r.set_defaults(func=cmd_report)

    st = sub.add_parser("status", help="show or change remediation status")
    common(st)
    st.add_argument("--set", nargs=2, metavar=("ID", "STATUS"), help=f"STATUS one of {', '.join(STATUSES)}")
    st.add_argument("--note")
    st.add_argument("--filter", choices=STATUSES)
    st.set_defaults(func=cmd_status)

    e = sub.add_parser("explain", help="show AI explanation of a finding, optionally ask a follow-up question")
    e.add_argument("id")
    common(e, positional=False)
    e.add_argument("-Q", "--question")
    e.set_defaults(func=cmd_explain)

    d = sub.add_parser("doctor", help="check Ollama connectivity and models")
    common(d)
    d.set_defaults(func=cmd_doctor)

    ru = sub.add_parser("rules", help="list built-in rules")
    ru.set_defaults(func=cmd_rules)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except BrokenPipeError:  # output piped into head/less
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return 0


if __name__ == "__main__":
    sys.exit(main())
