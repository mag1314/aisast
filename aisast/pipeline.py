"""End-to-end workflows used by the CLI and the benchmark harness."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Callable, Optional

from . import __version__
from .config import Config
from .llm.analysis import deep_scan, executive_summary, triage
from .llm.ollama import OllamaClient
from .models import Finding, ScanResult, severity_at_least
from .remediate import (FixResult, apply_to_tree, combine, generate_fix, git_commit, plan_groups, run_tests,
                        write_outputs)
from .report.formats import to_json, to_markdown, to_sarif
from .report.html import to_html
from .scanner import language_of, read_sources, scan_sources
from .tracking import bulk_set, merge_scan

Log = Callable[[str], None]


def ts() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S")


def workdir(root: Path) -> Path:
    return (root if root.is_dir() else root.parent) / ".aisast"


def make_client(cfg: Config, root: Path) -> OllamaClient:
    return OllamaClient(cfg.ollama_url, cfg.model, cfg.temperature, cfg.num_ctx, cfg.timeout,
                        workdir(root) / "cache" if cfg.cache else None)


def scan(root: Path, cfg: Config, log: Log = print, use_ai: Optional[bool] = None,
         client: Optional[OllamaClient] = None, track: bool = True) -> ScanResult:
    started = ts()
    t0 = time.time()
    sources = read_sources(root, cfg)
    log(f"[1/5] Static analysis: {len(sources)} files")
    findings, stats = scan_sources(sources, cfg)
    log(f"      {len(findings)} findings from the deterministic engine in {stats['static_seconds']}s")
    ai_info = {"enabled": False, "model": cfg.model, "ollama_url": cfg.ollama_url}
    suppressed: list[Finding] = []
    use_ai = cfg.ai_enabled if use_ai is None else use_ai
    if use_ai:
        client = client or make_client(cfg, root)
        h = client.health()
        ai_info["health"] = h
        if not h["ok"]:
            log(f"      ! AI disabled for this run: {h['message']}")
        else:
            ai_info["enabled"] = True
            languages = {p: language_of(Path(p)) for p in sources}
            if cfg.deep_scan:
                log(f"[2/5] AI deep scan with {cfg.model} (logic flaws, access control, anything rules miss)")
                t = time.time()
                new = deep_scan(sources, findings, client, cfg, languages, progress=lambda m: log("      " + m))
                ai_info["deep_scan"] = {"candidates_kept": len(new), "seconds": round(time.time() - t, 1)}
                log(f"      {len(new)} additional findings proposed by the model (validated against source)")
                findings += new
            else:
                log("[2/5] AI deep scan skipped (enable with --deep)")
            if cfg.triage and findings:
                log(f"[3/5] AI triage: verifying and explaining {len(findings)} findings")
                t = time.time()
                findings, suppressed = triage(findings, sources, client, cfg, progress=lambda m: log("      " + m))
                ai_info["triage"] = {"kept": len(findings), "suppressed": len(suppressed), "seconds": round(time.time() - t, 1)}
                log(f"      {len(suppressed)} suppressed as false positives, {len(findings)} confirmed/uncertain")
    else:
        log("[2/5] AI stages skipped (--no-ai)")
    findings = [f for f in findings if severity_at_least(f.severity, cfg.min_severity)]
    findings.sort(key=lambda f: (-f.risk_score, f.file, f.line))
    tracking = {}
    if track:
        log("[4/5] Updating remediation tracking")
        tracking = merge_scan(root, findings, suppressed, set(sources))
    if ai_info["enabled"]:
        ai_info["summary"] = executive_summary(findings, {"files": stats["files"], "findings": len(findings),
                                                          "suppressed": len(suppressed)}, client)
        ai_info["llm_stats"] = {k: round(v, 1) if isinstance(v, float) else v for k, v in client.stats.items()}
    stats["total_seconds"] = round(time.time() - t0, 2)
    result = ScanResult(str(root), findings, suppressed, stats, started, ts(), ai_info, tracking, __version__)
    save_last(root, result)
    return result


def save_last(root: Path, result: ScanResult) -> None:
    wd = workdir(root)
    wd.mkdir(parents=True, exist_ok=True)
    (wd / "last-scan.json").write_text(to_json(result))


def load_last(root: Path) -> Optional[ScanResult]:
    p = workdir(root) / "last-scan.json"
    if not p.exists():
        return None
    return ScanResult.from_dict(json.loads(p.read_text()))


def write_reports(root: Path, result: ScanResult, cfg: Config, formats: list[str], out: Optional[Path] = None) -> list[Path]:
    out = out or (root if root.is_dir() else root.parent) / cfg.output_dir
    out.mkdir(parents=True, exist_ok=True)
    sources = read_sources(root, cfg)
    written = []
    renders = {"json": ("aisast-report.json", lambda: to_json(result)),
               "sarif": ("aisast-report.sarif", lambda: to_sarif(result)),
               "md": ("aisast-report.md", lambda: to_markdown(result)),
               "html": ("aisast-report.html", lambda: to_html(result, sources))}
    for fmt in formats:
        if fmt in renders:
            name, fn = renders[fmt]
            (out / name).write_text(fn())
            written.append(out / name)
    return written


def fix(root: Path, cfg: Config, log: Log = print, use_ai: Optional[bool] = None, ids: Optional[list[str]] = None,
        apply: bool = False, git: bool = False, test_cmd: str = "", review: bool = True, max_groups: int = 0,
        client: Optional[OllamaClient] = None) -> dict:
    result = load_last(root)
    sources = read_sources(root, cfg)
    if result is None:
        log("No previous scan found — running a static scan first.")
        result = scan(root, cfg, log, use_ai=False)
    baseline, _ = scan_sources(sources, cfg)
    targets = [f for f in result.findings if (not ids or f.id in ids or f.fingerprint in ids)]
    groups = plan_groups(targets, sources, cfg.fix_min_severity)
    if max_groups:
        groups = groups[:max_groups]
    use_ai = cfg.ai_enabled if use_ai is None else use_ai
    if use_ai:
        client = client or make_client(cfg, root)
        h = client.health()
        if not h["ok"]:
            log(f"! AI unavailable ({h['message']}); using deterministic fix templates only")
            client = None
    else:
        client = None
    log(f"Generating fixes for {sum(len(g.findings) for g in groups)} findings in {len(groups)} code regions "
        f"({'LLM ' + cfg.remediation_model + ' + validation' if client else 'templates (offline)'})")
    results: list[FixResult] = []
    for i, g in enumerate(groups, 1):
        r = generate_fix(g, sources, cfg, client, baseline, review=review)
        results.append(r)
        mark = {"validated": "✔", "failed": "✘", "unsupported": "·"}[r.status]
        log(f"  {mark} [{i}/{len(groups)}] {g.file}:{g.start}-{g.end} {', '.join(f.rule_id for f in g.findings)}"
            f" — {r.status}{' (' + r.method + ', ' + str(r.attempts) + ' attempt' + ('s' if r.attempts != 1 else '') + ')' if r.method else ''}")
    patched = combine(results, sources)
    test_info = {}
    test_cmd = test_cmd or cfg.test_command
    if test_cmd and patched:
        log(f"Running tests with all patches applied: {test_cmd}")
        ok, output = run_tests(root, patched, test_cmd)
        test_info = {"command": test_cmd, "passed": ok, "output_tail": output[-1500:]}
        if not ok:
            log("  tests failed — isolating the offending patch(es)")
            for r in results:
                if r.status != "validated":
                    continue
                single = combine([r], sources)
                ok1, _ = run_tests(root, single, test_cmd)
                r.validation["tests"] = "pass" if ok1 else "fail"
                if not ok1:
                    r.status = "failed"
                    r.errors.append("tests failed with this patch")
                    log(f"  ✘ dropped {', '.join(r.group.ids)} ({r.group.file}:{r.group.start}) — tests fail with this patch")
            patched = combine(results, sources)
            ok, output = run_tests(root, patched, test_cmd) if patched else (True, "")
            test_info.update({"passed_after_isolation": ok})
        else:
            for r in results:
                if r.status == "validated":
                    r.validation["tests"] = "pass"
        log(f"  tests {'passed' if test_info.get('passed') or test_info.get('passed_after_isolation') else 'FAILED'}")
    outputs = write_outputs(root, workdir(root) / "fixes", results, sources, patched)
    # annotate findings with fix info for the reports
    by_id = {}
    for r in results:
        for f in r.group.findings:
            by_id[f.id] = {"status": r.status, "method": r.method, "summary": r.summary, "changes": r.changes,
                           "risk": r.risk, "diff": r.diff, "validation": r.validation, "attempts": r.attempts,
                           "start": r.group.start, "end": r.group.end, "replacement": r.replacement if r.status == "validated" else None,
                           "errors": r.errors[-3:], "seconds": r.seconds}
    for f in result.findings:
        if f.id in by_id:
            f.fix = by_id[f.id]
    validated_ids = [f.id for r in results if r.status == "validated" for f in r.group.findings]
    bulk_set(root, validated_ids, "fix_proposed", "aisast-fix", "validated patch generated")
    for f in result.findings:
        if f.id in validated_ids:
            f.status = "fix_proposed"
    applied, git_info = [], {}
    if apply and patched:
        applied = apply_to_tree(root, patched)
        bulk_set(root, validated_ids, "fixed", "aisast-fix", "patch applied to working tree")
        for f in result.findings:
            if f.id in validated_ids:
                f.status = "fixed"
        log(f"Applied patches to {len(applied)} files")
        if git:
            git_info = git_commit(root, applied, results, cfg.git_branch_prefix)
            log(f"Committed {git_info['commit']} on branch {git_info['branch']}" if git_info.get("ok") else f"git: {git_info.get('error')}")
    result.ai.setdefault("fix", {})
    result.ai["fix"] = {"groups": len(groups), "validated": sum(r.status == "validated" for r in results),
                        "llm": sum(r.method == "llm" and r.status == "validated" for r in results),
                        "template": sum(r.method == "template" and r.status == "validated" for r in results),
                        "tests": test_info}
    save_last(root, result)
    return {"results": results, "outputs": outputs, "applied": applied, "git": git_info, "tests": test_info,
            "validated_findings": len(validated_ids), "total_findings": sum(len(g.findings) for g in groups),
            "result": result}
