"""JSON, SARIF 2.1.0 and Markdown reports."""
from __future__ import annotations

import json
import re
from collections import Counter

from .. import __version__
from ..models import SEVERITIES, ScanResult
from ..rules import meta

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "7.5", "medium": "5.0", "low": "2.5", "info": "0.5"}


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def to_sarif(result: ScanResult) -> str:
    rules, rule_index = [], {}
    for f in result.findings:
        if f.rule_id not in rule_index:
            m = meta(f.rule_id)
            rule_index[f.rule_id] = len(rules)
            rules.append({
                "id": f.rule_id, "name": f.rule_id.replace("-", ""),
                "shortDescription": {"text": m["title"] if not f.rule_id.startswith("AI-") else f"{m['title']} (AI detected)"},
                "fullDescription": {"text": m["guidance"]},
                "help": {"text": m["guidance"], "markdown": f"**{m['title']}** ({m['cwe']})\n\n{m['guidance']}"},
                "properties": {"tags": ["security", m["cwe"], m["owasp"]], "security-severity": SECURITY_SEVERITY[m["severity"]],
                               "precision": "medium" if f.rule_id.startswith("AI-") else "high"},
            })
    results = []
    for f in result.findings:
        r = {
            "ruleId": f.rule_id, "ruleIndex": rule_index[f.rule_id], "level": SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.message}" + (f"\n\n{f.ai['explanation']}" if f.ai.get("explanation") else "")},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file},
                                                "region": {"startLine": f.line, "snippet": {"text": f.snippet}}}}],
            "partialFingerprints": {"aisast/v1": f.fingerprint},
            "properties": {"id": f.id, "severity": f.severity, "confidence": f.confidence, "cwe": f.cwe,
                           "risk_score": f.risk_score, "priority": f.priority, "status": f.status, "engine": f.engine,
                           "security-severity": SECURITY_SEVERITY[f.severity]},
        }
        if f.trace:
            locs = []
            for step in f.trace:
                entry = {"location": {"message": {"text": step[:200]}}}
                m = re.search(r"([\w./-]+\.\w+):(\d+)", step)
                if m:
                    entry["location"]["physicalLocation"] = {"artifactLocation": {"uri": m.group(1)},
                                                             "region": {"startLine": int(m.group(2))}}
                locs.append(entry)
            r["codeFlows"] = [{"threadFlows": [{"locations": locs}]}]
        if f.fix.get("status") == "validated" and f.fix.get("replacement") is not None:
            r["fixes"] = [{"description": {"text": f.fix.get("summary", "AI-SAST fix")},
                           "artifactChanges": [{"artifactLocation": {"uri": f.file}, "replacements": [{
                               "deletedRegion": {"startLine": f.fix["start"], "endLine": f.fix["end"]},
                               "insertedContent": {"text": f.fix["replacement"] + "\n"}}]}]}]
        results.append(r)
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "AI-SAST", "version": __version__, "informationUri": "https://localhost/aisast",
                                      "rules": rules}},
                  "results": results,
                  "properties": {"model": result.ai.get("model"), "ai_enabled": result.ai.get("enabled", False)}}],
    }
    return json.dumps(sarif, indent=2)


def to_markdown(result: ScanResult) -> str:
    fs = result.findings
    sev = Counter(f.severity for f in fs)
    lines = [f"# AI-SAST Security Report", "",
             f"- **Target:** `{result.root}`", f"- **Scanned:** {result.finished}",
             f"- **Files / lines:** {result.stats.get('files', 0)} / {result.stats.get('lines', 0)}",
             f"- **AI:** {'enabled — model `' + str(result.ai.get('model')) + '`' if result.ai.get('enabled') else 'disabled (deterministic engine only)'}",
             ""]
    summ = result.ai.get("summary") or {}
    if summ.get("executive_summary"):
        lines += ["## Executive summary", "", summ["executive_summary"], ""]
        if summ.get("recommended_actions"):
            lines += ["**Recommended actions**", ""] + [f"{i + 1}. {a}" for i, a in enumerate(summ["recommended_actions"])] + [""]
    lines += ["## Overview", "", "| Severity | Count |", "|---|---|"] + [f"| {s} | {sev.get(s, 0)} |" for s in SEVERITIES]
    tr = result.tracking or {}
    if tr:
        lines += ["", f"New: **{tr.get('new', 0)}** · Resolved since last scan: **{tr.get('resolved', 0)}** · "
                      f"Suppressed as false positive: **{len(result.suppressed)}**"]
    fixed = sum(1 for f in fs if f.fix.get("status") == "validated")
    if fixed:
        lines += [f"", f"Validated AI/auto fixes available for **{fixed}** of {len(fs)} findings."]
    lines += ["", "## Findings", "", "| ID | Sev | Risk | Title | Location | Status | Fix |", "|---|---|---|---|---|---|---|"]
    for f in fs:
        fx = "✅ " + f.fix.get("method", "") if f.fix.get("status") == "validated" else "—"
        lines.append(f"| {f.id} | {f.severity} | {f.risk_score} | {f.title} ({f.cwe}) | `{f.file}:{f.line}` | {f.status} | {fx} |")
    lines += ["", "## Details", ""]
    for f in fs:
        lines += [f"### {f.id} — {f.title}", "",
                  f"`{f.file}:{f.line}` · **{f.severity}** · confidence {f.confidence} · {f.cwe} · {f.owasp} · engine: {f.engine}", "",
                  f.message, "", "```", f.snippet, "```", ""]
        if f.trace:
            lines += ["**Data flow**", ""] + [f"{i + 1}. {t}" for i, t in enumerate(f.trace)] + [""]
        if f.ai.get("explanation"):
            lines += [f"**AI analysis** ({f.ai.get('verdict')}, {f.ai.get('confidence')}): {f.ai['explanation']}", ""]
            if f.ai.get("exploit_scenario"):
                lines += [f"*Exploit scenario:* {f.ai['exploit_scenario']}", ""]
        rec = f.ai.get("remediation") or meta(f.rule_id)["guidance"]
        lines += [f"**Recommended fix:** {rec}", ""]
        if f.fix.get("diff"):
            lines += [f"**Proposed patch** ({f.fix.get('method')}, validated: {f.fix.get('validation', {})})", "", "```diff", f.fix["diff"].rstrip(), "```", ""]
    if result.suppressed:
        lines += ["## Suppressed (AI triage: false positive)", ""]
        for f in result.suppressed:
            lines.append(f"- {f.id} {f.title} `{f.file}:{f.line}` — {f.ai.get('explanation', '')[:300]}")
    return "\n".join(lines) + "\n"
