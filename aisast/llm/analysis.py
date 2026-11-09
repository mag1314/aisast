"""LLM-driven analysis stages: triage (verify + explain), deep scan (discover
issues rules cannot express), executive summary and interactive Q&A."""
from __future__ import annotations

import re
from typing import Callable, Optional

from ..config import Config
from ..context import context_window, file_header, numbered, project_security_context
from ..models import Finding, SEVERITIES, SEVERITY_RANK, shift_severity
from ..rules import CATEGORIES, OWASP, category_for_cwe, meta
from . import prompts as P
from .ollama import OllamaClient, OllamaError

Progress = Optional[Callable[[str], None]]


def _trace_block(f: Finding) -> str:
    if not f.trace:
        return ""
    return "Data flow (source -> sink):\n" + "\n".join(f"  {i + 1}. {t}" for i, t in enumerate(f.trace))


def triage(findings: list[Finding], sources: dict[str, str], client: OllamaClient, cfg: Config,
           progress: Progress = None) -> tuple[list[Finding], list[Finding]]:
    """Ask the model to confirm/refute and explain each finding. Returns (kept, suppressed)."""
    kept, suppressed = [], []
    budget = cfg.max_ai_findings
    for i, f in enumerate(findings):
        if budget <= 0:
            kept.append(f)
            continue
        budget -= 1
        src = sources.get(f.file, "")
        if progress:
            progress(f"triage {i + 1}/{len(findings)} {f.id} {f.rule_id} {f.file}:{f.line}")
        code, _ = context_window(src, f.line, f.language or "text")
        prompt = P.TRIAGE_PROMPT.format(title=f.title, cwe=f.cwe, rule_id=f.rule_id, severity=f.severity,
                                        confidence=f.confidence, message=f.message, file=f.file, line=f.line,
                                        trace_block=_trace_block(f), language=f.language, code=code[:6000],
                                        header=file_header(src))
        try:
            r = client.chat_json(P.SYSTEM_ANALYST, prompt, P.TRIAGE_SCHEMA)
        except OllamaError as e:
            f.ai = {"error": str(e)}
            kept.append(f)
            continue
        apply_triage(f, r, cfg)
        (suppressed if f.status == "false_positive" else kept).append(f)
    return kept, suppressed


def apply_triage(f: Finding, r: dict, cfg: Config) -> None:
    verdict = str(r.get("verdict", "uncertain")).lower()
    try:
        conf = max(0.0, min(1.0, float(r.get("confidence", 0.5))))
    except (TypeError, ValueError):
        conf = 0.5
    sev = str(r.get("severity", f.severity)).lower()
    f.ai = {
        "verdict": verdict, "confidence": round(conf, 2),
        "explanation": str(r.get("explanation", ""))[:2000],
        "exploit_scenario": str(r.get("exploit_scenario", ""))[:1500],
        "root_cause": str(r.get("root_cause", ""))[:500],
        "remediation": str(r.get("remediation", ""))[:1500],
        "secure_example": str(r.get("secure_example", ""))[:1500],
        "model_severity": sev,
        "original_severity": f.severity,
    }
    # Guardrail: the model may move severity by at most one level.
    if sev in SEVERITIES and sev != f.severity and verdict == "true_positive":
        delta = SEVERITY_RANK[sev] - SEVERITY_RANK[f.severity]
        f.severity = shift_severity(f.severity, max(-1, min(1, delta)))
    if verdict == "true_positive" and conf >= 0.7 and f.confidence == "low":
        f.confidence = "medium"
    # Guardrail: suppress only with strong confidence; critical needs >= 0.85.
    need = max(cfg.fp_threshold, 0.85) if f.severity == "critical" else cfg.fp_threshold
    if verdict == "false_positive" and conf >= need:
        f.status = "false_positive"
        f.extra["suppressed_by"] = "ai-triage"
    f.compute_risk()


def _known_list(findings: list[Finding], path: str) -> str:
    items = [f"- line {f.line}: {f.title} ({f.cwe})" for f in findings if f.file == path]
    return "\n".join(items) if items else "- (none)"


def _chunks(src: str, language: str, size: int = 220, overlap: int = 15) -> list[tuple[int, int]]:
    n = len(src.splitlines())
    if n <= size:
        return [(1, n)]
    out, start = [], 1
    lines = src.splitlines()
    while start <= n:
        end = min(n, start + size - 1)
        if end < n:  # try to cut at a top-level boundary
            for j in range(end, max(start + size // 2, end - 60), -1):
                l = lines[j - 1]
                if l and not l[0].isspace() and re.match(r"(def |class |@|async def |function |app\.|router\.|export )", l):
                    end = j - 1
                    break
        out.append((start, end))
        if end >= n:
            break
        start = max(end - overlap + 1, start + 1)
    return out


def deep_scan(sources: dict[str, str], existing: list[Finding], client: OllamaClient, cfg: Config,
              languages: dict[str, str], progress: Progress = None) -> list[Finding]:
    """LLM discovery pass. Every candidate is validated against the real source
    (line range + verbatim evidence) to filter hallucinations."""
    sec_ctx = project_security_context(sources)
    files = [p for p in sources if languages.get(p) not in ("config", "", None)][: cfg.deep_scan_max_files]
    new: list[Finding] = []
    for fi, path in enumerate(files):
        src = sources[path]
        lines = src.splitlines()
        lang = languages[path]
        for (a, b) in _chunks(src, lang):
            if progress:
                progress(f"deep-scan {fi + 1}/{len(files)} {path} lines {a}-{b}")
            prompt = P.DEEP_PROMPT.format(language=lang, file=path, security_context=sec_ctx,
                                          known=_known_list(existing + new, path), code=numbered(src, a, b))
            try:
                r = client.chat_json(P.SYSTEM_ANALYST, prompt, P.DEEP_SCHEMA)
            except OllamaError:
                continue
            for item in (r.get("findings") or [])[:25]:
                f = _validate_candidate(item, path, lang, lines, a, b, existing + new)
                if f:
                    new.append(f)
    return new


def _norm(s: str) -> str:
    return re.sub(r"\s+", "", s or "")


def _validate_candidate(item: dict, path: str, lang: str, lines: list[str], a: int, b: int, known: list[Finding]):
    try:
        line = int(item.get("line", 0))
        conf = float(item.get("confidence", 0))
    except (TypeError, ValueError):
        return None
    if conf < 0.6:
        return None
    evidence = _norm(str(item.get("evidence", "")))[:200]
    if evidence:
        # snap to the line that really contains the evidence (models are often off by a few lines)
        window = range(max(a, line - 4), min(b, line + 4) + 1)
        hit = next((i for i in sorted(window, key=lambda i: abs(i - line)) if evidence[:60] in _norm(lines[i - 1])), None)
        if hit is None:
            hit = next((i for i in range(a, b + 1) if len(evidence) >= 12 and evidence[:60] in _norm(lines[i - 1])), None)
        if hit is None:
            return None  # hallucinated evidence
        line = hit
    elif not (a <= line <= b):
        return None
    cat = str(item.get("category", "")).lower()
    if cat not in CATEGORIES:
        cat = category_for_cwe(str(item.get("cwe", "")))
    for k in known:
        if k.file == path and abs(k.line - line) <= 2 and (k.category == cat or cat == "other"):
            return None
    m = meta("AI-" + cat.upper())
    sev = str(item.get("severity", m["severity"])).lower()
    sev = sev if sev in SEVERITIES else m["severity"]
    cwe = str(item.get("cwe") or m["cwe"]).upper()
    if not re.fullmatch(r"CWE-\d+", cwe):
        cwe = m["cwe"]
    f = Finding(rule_id="AI-" + cat.upper(), title=str(item.get("title") or m["title"])[:120], severity=sev,
                confidence="high" if conf >= 0.85 else "medium" if conf >= 0.7 else "low", file=path, line=line,
                message=str(item.get("description", ""))[:600], cwe=cwe,
                owasp=m["owasp"], category=cat, language=lang, snippet=lines[line - 1].strip()[:200], engine="llm",
                extra={"llm_confidence": conf})
    f.compute_fingerprint()
    f.compute_risk()
    return f


def executive_summary(findings: list[Finding], stats: dict, client: OllamaClient) -> dict:
    top = "\n".join(f"{f.id} | {f.severity} | {f.title} | {f.file}:{f.line}" for f in findings[:15]) or "(none)"
    try:
        return client.chat_json(P.SYSTEM_ANALYST, P.SUMMARY_PROMPT.format(stats=stats, top=top))
    except OllamaError as e:
        return {"error": str(e)}


def ask(f: Finding, question: str, source: str, client: OllamaClient) -> str:
    code, _ = context_window(source, f.line, f.language)
    r = client.chat_json(P.SYSTEM_ANALYST, P.ASK_PROMPT.format(
        title=f.title, cwe=f.cwe, file=f.file, line=f.line, message=f.message, trace_block=_trace_block(f),
        language=f.language, code=code, analysis=f.ai.get("explanation", "n/a"), question=question))
    return str(r.get("answer", r))
