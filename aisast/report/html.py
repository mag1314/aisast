"""Self-contained HTML security report (no external assets; works offline)."""
from __future__ import annotations

import html
import json
from collections import Counter

from .. import __version__
from ..models import SEVERITIES, ScanResult
from ..rules import meta

E = lambda s: html.escape(str(s if s is not None else ""), quote=True)  # noqa: E731

CSS = """
:root{--bg:#f6f7f9;--panel:#fff;--ink:#16181d;--muted:#5d6572;--line:#e3e6eb;--code:#f3f4f6;
--crit:#b42318;--high:#d9480f;--med:#b98900;--low:#1f6feb;--info:#6b7280;--ok:#18794e;--accent:#3b3bd6;
--add:#e6f4ea;--del:#fdecea;--mark:#fff4c2}
@media (prefers-color-scheme:dark){:root{--bg:#0f1115;--panel:#171a21;--ink:#e7e9ee;--muted:#9aa3b2;--line:#2a2f3a;
--code:#11141a;--add:#12301f;--del:#3a1717;--mark:#3a3210;--accent:#8b8bff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
code,pre,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
header{padding:28px 32px 20px;border-bottom:1px solid var(--line);background:var(--panel)}
header h1{margin:0 0 4px;font-size:22px;letter-spacing:-.01em}header .meta{color:var(--muted);display:flex;gap:18px;flex-wrap:wrap}
main{max-width:1180px;margin:0 auto;padding:24px 20px 64px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.kpi .v{font-size:26px;font-weight:650;font-variant-numeric:tabular-nums}.kpi .l{color:var(--muted);font-size:12.5px}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:18px 20px;margin-bottom:20px}
.panel h2{font-size:15px;margin:0 0 12px}
.bar{display:flex;height:12px;border-radius:6px;overflow:hidden;background:var(--line);margin:6px 0 10px}
.legend{display:flex;gap:16px;flex-wrap:wrap;color:var(--muted);font-size:12.5px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px;vertical-align:baseline}
.sev{display:inline-block;min-width:66px;text-align:center;padding:1px 8px;border-radius:999px;font-size:11.5px;font-weight:600;color:#fff;text-transform:uppercase;letter-spacing:.03em}
.s-critical{background:var(--crit)}.s-high{background:var(--high)}.s-medium{background:var(--med)}.s-low{background:var(--low)}.s-info{background:var(--info)}
.tag{display:inline-block;padding:1px 7px;border:1px solid var(--line);border-radius:6px;font-size:11.5px;color:var(--muted);margin-right:4px}
.tag.ok{color:var(--ok);border-color:var(--ok)}.tag.ai{color:var(--accent);border-color:var(--accent)}
.controls{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.controls input,.controls select{background:var(--panel);color:var(--ink);border:1px solid var(--line);border-radius:8px;padding:7px 10px;font:inherit}
.controls input{flex:1;min-width:200px}
details.f{background:var(--panel);border:1px solid var(--line);border-radius:10px;margin-bottom:8px}
details.f>summary{list-style:none;cursor:pointer;padding:12px 16px;display:grid;grid-template-columns:84px 1fr auto;gap:12px;align-items:center}
details.f>summary::-webkit-details-marker{display:none}
details.f[open]>summary{border-bottom:1px solid var(--line)}
.t1{font-weight:600}.t2{color:var(--muted);font-size:12.5px;overflow-wrap:anywhere}
.right{text-align:right;white-space:nowrap}.risk{font-weight:650;font-variant-numeric:tabular-nums}
.body{padding:14px 18px 18px;display:grid;gap:14px}
.body h3{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:0 0 6px}
pre.code{background:var(--code);border:1px solid var(--line);border-radius:8px;padding:10px 0;margin:0;overflow:auto}
pre.code span{display:block;padding:0 12px;white-space:pre}pre.code .hl{background:var(--mark)}
pre.code .ln{color:var(--muted);display:inline;padding:0 10px 0 0;user-select:none}
pre.diff span.a{background:var(--add)}pre.diff span.d{background:var(--del)}pre.diff span.h{color:var(--muted)}
ol.trace{margin:0;padding-left:20px}ol.trace li{margin:2px 0;overflow-wrap:anywhere}
.ai{border-left:3px solid var(--accent);padding:2px 0 2px 12px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px}@media(max-width:760px){.grid2{grid-template-columns:1fr}details.f>summary{grid-template-columns:70px 1fr}.right{grid-column:2;text-align:left}}
table{border-collapse:collapse;width:100%}td,th{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;font-size:13px}
.muted{color:var(--muted)}.empty{padding:30px;text-align:center;color:var(--muted)}
footer{color:var(--muted);text-align:center;font-size:12px;margin-top:30px}
"""

JS = """
const q=document.getElementById('q'),sv=document.getElementById('sev'),st=document.getElementById('st'),fx=document.getElementById('fx');
function apply(){const t=q.value.toLowerCase();let n=0;document.querySelectorAll('details.f').forEach(d=>{
 const ok=(!t||d.dataset.text.includes(t))&&(!sv.value||d.dataset.sev===sv.value)&&(!st.value||d.dataset.status===st.value)
 &&(!fx.value||(fx.value==='yes')===(d.dataset.fix==='yes'));d.style.display=ok?'':'none';if(ok)n++});
 document.getElementById('count').textContent=n+' shown'}
[q,sv,st,fx].forEach(e=>e.addEventListener('input',apply));apply();
document.getElementById('expand').onclick=()=>document.querySelectorAll('details.f').forEach(d=>{if(d.style.display!=='none')d.open=true});
document.getElementById('collapse').onclick=()=>document.querySelectorAll('details.f').forEach(d=>d.open=false);
"""


def _code(source: str, line: int, pad: int = 4) -> str:
    lines = source.splitlines()
    if not lines or line < 1:
        return ""
    a, b = max(1, line - pad), min(len(lines), line + pad)
    rows = [f'<span class="{"hl" if i == line else ""}"><span class="ln">{i:4d}</span>{E(lines[i - 1])}</span>' for i in range(a, b + 1)]
    return '<pre class="code">' + "".join(rows) + "</pre>"


def _diff(d: str) -> str:
    rows = []
    for l in d.splitlines():
        cls = "a" if l.startswith("+") and not l.startswith("+++") else "d" if l.startswith("-") and not l.startswith("---") else "h" if l.startswith(("@@", "diff", "---", "+++")) else ""
        rows.append(f'<span class="{cls}">{E(l)}</span>')
    return '<pre class="code diff">' + "".join(rows) + "</pre>"


def _finding(f, sources: dict) -> str:
    m = meta(f.rule_id)
    fix_ok = f.fix.get("status") == "validated"
    tags = [f'<span class="tag">{E(f.cwe)}</span>', f'<span class="tag">{E(f.engine)}</span>', f'<span class="tag">{E(f.status)}</span>']
    if f.ai.get("verdict"):
        tags.append(f'<span class="tag ai">AI: {E(f.ai["verdict"].replace("_", " "))} {E(f.ai.get("confidence", ""))}</span>')
    if fix_ok:
        tags.append(f'<span class="tag ok">fix ready · {E(f.fix.get("method"))}</span>')
    text = " ".join([f.id, f.title, f.file, f.message, f.rule_id, f.cwe, f.snippet]).lower()
    parts = [f'<details class="f" data-sev="{E(f.severity)}" data-status="{E(f.status)}" data-fix="{"yes" if fix_ok else "no"}" data-text="{E(text)}">',
             f'<summary><span class="sev s-{E(f.severity)}">{E(f.severity)}</span>'
             f'<div><div class="t1">{E(f.title)} <span class="muted mono">{E(f.id)}</span></div>'
             f'<div class="t2 mono">{E(f.file)}:{f.line}{" · " + E(f.function) if f.function and f.function != "<module>" else ""}</div></div>'
             f'<div class="right"><div class="risk">{f.risk_score}</div><div class="t2">{E(f.priority)} · {E(f.confidence)} conf.</div></div></summary>',
             '<div class="body">', f'<div>{" ".join(tags)}<span class="tag">{E(f.owasp)}</span></div>',
             f'<div><h3>Issue</h3>{E(f.message)}</div>', f'<div><h3>Code</h3>{_code(sources.get(f.file, ""), f.line) or "<pre class=code><span>" + E(f.snippet) + "</span></pre>"}</div>']
    if f.trace:
        parts.append('<div><h3>Data flow (source → sink)</h3><ol class="trace mono">' + "".join(f"<li>{E(t)}</li>" for t in f.trace) + "</ol></div>")
    if f.ai.get("explanation"):
        ai = [f'<div class="ai"><h3>AI analysis</h3><p>{E(f.ai["explanation"])}</p>']
        if f.ai.get("exploit_scenario"):
            ai.append(f'<p><b>Exploit scenario.</b> {E(f.ai["exploit_scenario"])}</p>')
        if f.ai.get("root_cause"):
            ai.append(f'<p><b>Root cause.</b> {E(f.ai["root_cause"])}</p>')
        ai.append("</div>")
        parts.append("".join(ai))
    parts.append(f'<div><h3>Recommended fix</h3>{E(f.ai.get("remediation") or m["guidance"])}</div>')
    if f.fix.get("diff"):
        v = f.fix.get("validation", {})
        badges = " ".join(f'<span class="tag {"ok" if str(val) == "pass" else ""}">{E(k)}: {E(str(val)[:60])}</span>'
                          for k, val in v.items() if k in ("syntax", "rescan", "ai_review", "tests"))
        parts.append(f'<div><h3>Ready-to-apply patch — {E(f.fix.get("summary", ""))}</h3><div style="margin-bottom:6px">{badges}</div>{_diff(f.fix["diff"])}</div>')
    elif f.fix.get("status"):
        parts.append(f'<div><h3>Automated fix</h3><span class="muted">{E(f.fix.get("status"))} — manual remediation required.</span></div>')
    parts.append("</div></details>")
    return "".join(parts)


def to_html(result: ScanResult, sources: dict) -> str:
    fs = result.findings
    sev = Counter(f.severity for f in fs)
    total = len(fs) or 1
    colors = {"critical": "var(--crit)", "high": "var(--high)", "medium": "var(--med)", "low": "var(--low)", "info": "var(--info)"}
    bar = "".join(f'<div style="width:{sev.get(s, 0) / total * 100:.2f}%;background:{colors[s]}" title="{s}: {sev.get(s, 0)}"></div>' for s in SEVERITIES)
    legend = "".join(f'<span><span class="dot" style="background:{colors[s]}"></span>{s} {sev.get(s, 0)}</span>' for s in SEVERITIES)
    fixes = sum(1 for f in fs if f.fix.get("status") == "validated")
    tr = result.tracking or {}
    ai = result.ai or {}
    kpis = [(len(fs), "open findings"), (sev.get("critical", 0) + sev.get("high", 0), "critical + high"),
            (fixes, "validated fixes ready"), (len(result.suppressed), "false positives suppressed by AI"),
            (tr.get("resolved", 0), "resolved since last scan"), (result.stats.get("files", 0), "files scanned")]
    kpi_html = "".join(f'<div class="kpi"><div class="v">{v}</div><div class="l">{E(l)}</div></div>' for v, l in kpis)
    summary = ai.get("summary") or {}
    exec_html = ""
    if summary.get("executive_summary"):
        acts = "".join(f"<li>{E(a)}</li>" for a in summary.get("recommended_actions", []))
        exec_html = f'<div class="panel"><h2>Executive summary <span class="tag ai">AI generated</span></h2><p>{E(summary["executive_summary"])}</p>' + \
                    (f"<h3 class='muted' style='font-size:12px;text-transform:uppercase'>Recommended actions</h3><ol>{acts}</ol>" if acts else "") + "</div>"
    by_cat = Counter(f.title for f in fs).most_common(8)
    by_file = Counter(f.file for f in fs).most_common(8)
    cat_rows = "".join(f"<tr><td>{E(c)}</td><td class=right>{n}</td></tr>" for c, n in by_cat)
    file_rows = "".join(f"<tr><td class=mono>{E(c)}</td><td class=right>{n}</td></tr>" for c, n in by_file)
    statuses = sorted({f.status for f in fs})
    body = "".join(_finding(f, sources) for f in fs) or '<div class="empty">No findings. 🎉</div>'
    supp = ""
    if result.suppressed:
        rows = "".join(f"<tr><td class=mono>{E(f.id)}</td><td>{E(f.title)}</td><td class=mono>{E(f.file)}:{f.line}</td><td>{E(f.ai.get('explanation', '')[:260])}</td></tr>" for f in result.suppressed)
        supp = f'<div class="panel"><h2>Suppressed as false positives by AI triage ({len(result.suppressed)})</h2><p class="muted">Kept for audit. Re-open with <code>aisast status --set ID open</code>.</p><table><tr><th>ID</th><th>Rule</th><th>Location</th><th>AI reasoning</th></tr>{rows}</table></div>'
    hist = ""
    if tr.get("history"):
        rows = "".join(f"<tr><td>{E(h['at'])}</td><td class=right>{h['findings']}</td><td class=right>{h['new']}</td><td class=right>{h['resolved']}</td></tr>" for h in tr["history"])
        sc = tr.get("status_counts", {})
        hist = f'<div class="panel"><h2>Remediation tracking</h2><div class="legend" style="margin-bottom:10px">' + \
               "".join(f"<span>{E(k)}: <b>{v}</b></span>" for k, v in sc.items() if v) + \
               f'</div><table><tr><th>Scan</th><th class=right>Findings</th><th class=right>New</th><th class=right>Resolved</th></tr>{rows}</table></div>'
    ai_line = f"AI: {E(ai.get('model'))} via Ollama ({E(ai.get('ollama_url'))})" if ai.get("enabled") else "AI: disabled (deterministic engine only)"
    if ai.get("enabled") and ai.get("llm_stats"):
        s = ai["llm_stats"]
        ai_line += f" · {s.get('calls', 0)} LLM calls, {s.get('cache_hits', 0)} cached, {s.get('seconds', 0):.0f}s"
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>AI-SAST report — {E(result.root)}</title><style>{CSS}</style></head><body>
<header><h1>AI-SAST security report</h1><div class="meta"><span class="mono">{E(result.root)}</span><span>{E(result.finished)}</span>
<span>{result.stats.get('files', 0)} files · {result.stats.get('lines', 0)} lines</span><span>{ai_line}</span></div></header>
<main><div class="kpis">{kpi_html}</div>{exec_html}
<div class="panel"><h2>Severity distribution</h2><div class="bar">{bar}</div><div class="legend">{legend}</div>
<div class="grid2" style="margin-top:14px"><div><h3 class="muted" style="font-size:12px;text-transform:uppercase">Top categories</h3><table>{cat_rows}</table></div>
<div><h3 class="muted" style="font-size:12px;text-transform:uppercase">Most affected files</h3><table>{file_rows}</table></div></div></div>
<div class="controls"><input id="q" placeholder="Filter by id, file, rule, CWE…"><select id="sev"><option value="">All severities</option>{"".join(f'<option>{s}</option>' for s in SEVERITIES)}</select>
<select id="st"><option value="">All statuses</option>{"".join(f'<option>{E(s)}</option>' for s in statuses)}</select>
<select id="fx"><option value="">Fix: any</option><option value="yes">Fix ready</option><option value="no">No fix</option></select>
<span class="muted" id="count"></span><button id="expand" class="tag">expand</button><button id="collapse" class="tag">collapse</button></div>
{body}{supp}{hist}
<footer>Generated by AI-SAST {__version__} · all analysis performed locally · <span class="mono">data: {E(json.dumps(result.stats.get('languages', {})))}</span></footer>
</main><script>{JS}</script></body></html>"""
