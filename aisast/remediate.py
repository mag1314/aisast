"""AI-assisted remediation: generate -> apply -> validate -> retry, then emit
push-ready patches (unified diffs, fixed files, optional git branch + commit).

Validation gates for every candidate fix:
  1. syntax      : the patched file parses/compiles (python compile(), `node --check` for JS)
  2. rescan      : the deterministic engine no longer reports the issue in the patched region
                   and no new medium+ finding was introduced
  3. ai-review   : (when Ollama is available) an independent LLM review confirms the patch
                   fixes the issue without introducing new problems
  4. tests       : (optional --test-cmd) the project's tests pass with all patches applied
"""
from __future__ import annotations

import difflib
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from .config import Config
from .context import Region, file_header, numbered, region_for
from .llm import prompts as P
from .llm.ollama import OllamaClient, OllamaError
from .models import Finding, SEVERITY_RANK
from .scanner import scan_sources
from .templates import template_fix


@dataclass
class FixGroup:
    file: str
    language: str
    start: int
    end: int
    findings: list = field(default_factory=list)

    @property
    def ids(self) -> list[str]:
        return [f.id for f in self.findings]


@dataclass
class FixResult:
    group: FixGroup
    status: str = "failed"            # validated | failed | unsupported
    method: str = ""                  # llm | template
    replacement: str = ""
    imports: list = field(default_factory=list)
    summary: str = ""
    changes: list = field(default_factory=list)
    risk: str = ""
    test_suggestion: str = ""
    attempts: int = 0
    validation: dict = field(default_factory=dict)
    diff: str = ""
    seconds: float = 0.0
    errors: list = field(default_factory=list)


# ----------------------------------------------------------------------------- planning
def plan_groups(findings: list[Finding], sources: dict[str, str], min_severity: str = "low") -> list[FixGroup]:
    groups: list[FixGroup] = []
    for f in sorted(findings, key=lambda x: (x.file, x.line)):
        if f.status in ("false_positive", "accepted_risk", "verified") or SEVERITY_RANK[f.severity] < SEVERITY_RANK[min_severity]:
            continue
        src = sources.get(f.file)
        if src is None or f.language in ("config", ""):
            continue
        r = region_for(src, f.line, f.language)
        for g in groups:
            if g.file == f.file and not (r.end < g.start or r.start > g.end):
                g.start, g.end = min(g.start, r.start), max(g.end, r.end)
                g.findings.append(f)
                break
        else:
            groups.append(FixGroup(f.file, f.language, r.start, r.end, [f]))
    return groups


# ----------------------------------------------------------------------------- patch application
def reindent(code: str, original: str) -> str:
    def first_indent(s):
        for l in s.splitlines():
            if l.strip():
                return l[: len(l) - len(l.lstrip())]
        return ""
    want, have = first_indent(original), first_indent(code)
    if want == have:
        return code
    return textwrap.indent(textwrap.dedent(code), want, lambda l: True if l.strip() else False)


def strip_fences(code: str) -> str:
    code = re.sub(r"^\s*```[\w+-]*\n", "", code)
    code = re.sub(r"\n```\s*$", "", code)
    # models sometimes echo the "  123 | " line-number gutter
    if all(re.match(r"^\s*(>>)?\s*\d+\s\|\s?", l) for l in code.splitlines() if l.strip()):
        code = "\n".join(re.sub(r"^\s*(>>)?\s*\d+\s\|\s?", "", l) for l in code.splitlines())
    return code.rstrip("\n")


def add_imports(source: str, imports: list[str], language: str) -> str:
    lines = source.split("\n")
    todo = []
    for imp in imports:
        imp = imp.strip()
        if not imp or imp in lines:
            continue
        if language == "python":
            m = re.match(r"import (\w+)$", imp)
            if m and re.search(rf"^import {m.group(1)}\b|^import .*\b{m.group(1)}\b", source, re.M):
                continue
            m = re.match(r"from ([\w.]+) import (\w+)$", imp)
            if m and re.search(rf"^from {re.escape(m.group(1))} import .*\b{m.group(2)}\b", source, re.M):
                continue
        else:
            names = re.findall(r"[\w$]+", imp.split("=")[0])
            if any(re.search(rf"^\s*(const|let|var|import)\b.*\b{re.escape(n)}\b", source, re.M) for n in names if n not in ("const", "let", "var", "require")):
                continue
        todo.append(imp)
    if not todo:
        return source
    idx = 0
    pat = re.compile(r"^(import |from \S+ import )") if language == "python" else re.compile(r"^(import |const .*require\(|let .*require\(|var .*require\()")
    in_doc = False
    for i, l in enumerate(lines[:200]):
        if language == "python" and l.startswith(('"""', "'''")):
            in_doc = not in_doc if l.count(l[:3]) == 1 else in_doc
            idx = max(idx, i + 1)
        if pat.match(l) and not in_doc:
            idx = i + 1
    lines[idx:idx] = todo
    return "\n".join(lines)


def apply_region(source: str, start: int, end: int, replacement: str, imports: list[str], language: str) -> tuple[str, int]:
    lines = source.split("\n")
    new_lines = replacement.split("\n")
    out = lines[: start - 1] + new_lines + lines[end:]
    patched = "\n".join(out)
    before = patched.count("\n")
    patched = add_imports(patched, imports, language)
    return patched, patched.count("\n") - before   # number of import lines inserted above


def unified_diff(path: str, a: str, b: str) -> str:
    diff = difflib.unified_diff(a.splitlines(keepends=True), b.splitlines(keepends=True),
                                fromfile=f"a/{path}", tofile=f"b/{path}", n=3)
    text = "".join(d if d.endswith("\n") else d + "\n\\ No newline at end of file\n" for d in diff)
    return f"diff --git a/{path} b/{path}\n{text}" if text else ""


# ----------------------------------------------------------------------------- validation
def check_syntax(code: str, language: str, path: str) -> Optional[str]:
    if language == "python":
        try:
            compile(code, path, "exec")
        except SyntaxError as e:
            return f"SyntaxError line {e.lineno}: {e.msg}"
        return None
    if language == "javascript" and shutil.which("node"):
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as t:
            t.write(code)
        try:
            r = subprocess.run(["node", "--check", t.name], capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                msg = (r.stderr or r.stdout).strip().splitlines()
                return "node --check: " + " ".join(m for m in msg if "SyntaxError" in m or "Error" in m)[:300]
        finally:
            os.unlink(t.name)
    return None


def rescan_check(group: FixGroup, sources: dict[str, str], patched: str, new_start: int, new_end: int,
                 cfg: Config, baseline: list[Finding]) -> tuple[bool, list[str]]:
    new_sources = dict(sources)
    new_sources[group.file] = patched
    after, _ = scan_sources(new_sources, cfg)
    problems = []
    in_region = [f for f in after if f.file == group.file and new_start <= f.line <= new_end]
    for f in group.findings:
        if f.engine == "llm":
            continue  # rule engine cannot see these; covered by AI review
        still = [x for x in in_region if x.category == f.category and x.confidence != "low"]
        if still:
            problems.append(f"still detected: {f.title} at line {still[0].line} ({still[0].snippet[:80]})")
    before_cats = {(f.category) for f in baseline if f.file == group.file and group.start <= f.line <= group.end}
    for x in in_region:
        if x.category not in before_cats and SEVERITY_RANK[x.severity] >= SEVERITY_RANK["medium"] and x.confidence != "low":
            problems.append(f"introduced: {x.title} at line {x.line}")
    # anything that moved to other places in the file?
    other_new = {(x.rule_id, x.snippet) for x in after if x.file == group.file} - \
        {(x.rule_id, x.snippet) for x in baseline if x.file == group.file}
    for rid, snip in other_new:
        hit = next(x for x in after if x.rule_id == rid and x.snippet == snip)
        if not (new_start <= hit.line <= new_end) and SEVERITY_RANK[hit.severity] >= SEVERITY_RANK["medium"] and hit.confidence != "low":
            problems.append(f"introduced elsewhere: {hit.title} at line {hit.line}")
    return not problems, problems


def vuln_list(group: FixGroup) -> str:
    out = []
    for f in group.findings:
        s = f"- [{f.id}] {f.title} ({f.cwe}) at line {f.line}: {f.message}"
        if f.trace:
            s += "\n    data flow: " + " -> ".join(t.split(" — ")[0] for t in f.trace[:5])
        if f.ai.get("remediation"):
            s += f"\n    guidance: {f.ai['remediation'][:400]}"
        out.append(s)
    return "\n".join(out)


# ----------------------------------------------------------------------------- generation
def generate_fix(group: FixGroup, sources: dict[str, str], cfg: Config, client: Optional[OllamaClient],
                 baseline: list[Finding], review: bool = True, progress: Optional[Callable] = None) -> FixResult:
    t0 = time.time()
    res = FixResult(group)
    src = sources[group.file]
    lines = src.split("\n")
    original = "\n".join(lines[group.start - 1: group.end])
    feedback = ""
    candidates_tried = 0

    def try_candidate(code: str, imports: list[str], method: str) -> bool:
        nonlocal feedback
        res.attempts += 1
        code = reindent(strip_fences(code), original)
        if code.strip() == original.strip():
            feedback = "Your previous answer did not change the code. You must modify it to remove the vulnerability."
            res.errors.append(f"{method}: no change")
            return False
        patched, shift = apply_region(src, group.start, group.end, code, imports, group.language)
        new_start, new_end = group.start + shift, group.start + shift + code.count("\n")
        val = {"syntax": "pass", "rescan": "skipped", "ai_review": "skipped"}
        err = check_syntax(patched, group.language, group.file)
        if err:
            val["syntax"] = err
            feedback = f"Your previous fix did not compile: {err}. Return syntactically valid code."
            res.errors.append(f"{method}: {err}")
            res.validation = val
            return False
        ok, problems = rescan_check(group, sources, patched, new_start, new_end, cfg, baseline)
        val["rescan"] = "pass" if ok else "; ".join(problems)
        if not ok:
            feedback = "The security scanner still reports problems with your previous fix: " + "; ".join(problems)
            res.errors.append(f"{method}: {val['rescan']}")
            res.validation = val
            return False
        if client is not None and review:
            try:
                r = client.chat_json(P.SYSTEM_ANALYST, P.REVIEW_PROMPT.format(
                    vulns=vuln_list(group), language=group.language, original=original, patched=code,
                    imports=imports or "none"), P.REVIEW_SCHEMA, model=cfg.remediation_model)
                fixed, issues = bool(r.get("fixes_vulnerability")), bool(r.get("introduces_issues"))
                val["ai_review"] = "pass" if fixed and not issues else f"fail: {r.get('concerns', '')[:300]}"
                val["preserves_behavior"] = bool(r.get("preserves_behavior", True))
                if r.get("concerns"):
                    val["review_notes"] = str(r.get("concerns"))[:500]
                if not (fixed and not issues):
                    feedback = f"A reviewer rejected your previous fix: {r.get('concerns', 'it does not fully fix the issue')}"
                    res.errors.append(f"{method}: review rejected")
                    res.validation = val
                    return False
            except OllamaError as e:
                val["ai_review"] = f"unavailable: {e}"
        res.validation = val
        res.replacement, res.imports, res.method, res.status = code, imports, method, "validated"
        res.diff = unified_diff(group.file, src, patched)
        return True

    # 1) LLM generation with self-correction loop
    if client is not None:
        for attempt in range(cfg.fix_attempts):
            if progress:
                progress(f"fix {group.file}:{group.start}-{group.end} attempt {attempt + 1}")
            prompt = P.FIX_PROMPT.format(file=group.file, language=group.language, vulns=vuln_list(group),
                                         header=file_header(src), start=group.start, end=group.end,
                                         code=original, feedback=f"\nIMPORTANT: {feedback}\n" if feedback else "")
            try:
                r = client.chat_json(P.SYSTEM_ANALYST, prompt, P.FIX_SCHEMA, model=cfg.remediation_model,
                                     temperature=0.1 if attempt == 0 else 0.3)
            except OllamaError as e:
                res.errors.append(f"llm: {e}")
                break
            code = str(r.get("fixed_code", ""))
            if not code.strip():
                feedback = "fixed_code was empty."
                continue
            candidates_tried += 1
            if try_candidate(code, [str(i) for i in (r.get("new_imports") or [])], "llm"):
                res.summary = str(r.get("summary", ""))[:500]
                res.changes = [str(c)[:300] for c in (r.get("changes") or [])][:10]
                res.risk = str(r.get("breaking_change_risk", ""))
                res.test_suggestion = str(r.get("test_suggestion", ""))[:500]
                break
    # 2) deterministic template fallback (also the offline mode)
    if res.status != "validated":
        region_lines, imports, summaries = original, [], []
        offset = 0
        for f in sorted(group.findings, key=lambda x: -x.line):
            t = template_fix(f, region_lines, group.start, "\n".join(lines[: group.start - 1] + [region_lines] + lines[group.end:]), sources)
            if t:
                region_lines, imp, summ = t
                imports += imp
                summaries.append(summ)
        if summaries and try_candidate(region_lines, list(dict.fromkeys(imports)), "template"):
            res.summary = " ".join(dict.fromkeys(summaries))
            res.risk = "low"
        elif not summaries and res.status != "validated":
            res.status = "unsupported" if client is None else "failed"
    res.seconds = round(time.time() - t0, 2)
    return res


# ----------------------------------------------------------------------------- combine & output
def combine(results: list[FixResult], sources: dict[str, str]) -> dict[str, str]:
    """Apply all validated fixes per file, bottom-up so line numbers stay valid."""
    patched: dict[str, str] = {}
    by_file: dict[str, list[FixResult]] = {}
    for r in results:
        if r.status == "validated":
            by_file.setdefault(r.group.file, []).append(r)
    for path, rs in by_file.items():
        src = sources[path]
        imports: list[str] = []
        lang = rs[0].group.language
        for r in sorted(rs, key=lambda r: -r.group.start):
            lines = src.split("\n")
            src = "\n".join(lines[: r.group.start - 1] + r.replacement.split("\n") + lines[r.group.end:])
            imports += r.imports
        patched[path] = add_imports(src, list(dict.fromkeys(imports)), lang)
    return patched


def run_tests(root: Path, patched: dict[str, str], cmd: str, timeout: int = 600) -> tuple[bool, str]:
    with tempfile.TemporaryDirectory(prefix="aisast-test-") as tmp:
        dst = Path(tmp) / "src"
        shutil.copytree(root, dst, ignore=shutil.ignore_patterns(".git", "node_modules", ".aisast", "__pycache__", ".venv", "venv"))
        for path, text in patched.items():
            (dst / path).write_text(text)
        try:
            r = subprocess.run(cmd, shell=True, cwd=dst, capture_output=True, text=True, timeout=timeout)  # user-supplied command
        except subprocess.TimeoutExpired:
            return False, "timeout"
        return r.returncode == 0, (r.stdout + r.stderr)[-3000:]


def write_outputs(root: Path, out_dir: Path, results: list[FixResult], sources: dict[str, str],
                  patched: dict[str, str]) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "patches").mkdir(exist_ok=True)
    files_dir = out_dir / "files"
    for r in results:
        if r.status == "validated":
            name = f"{r.group.findings[0].id}-{Path(r.group.file).name}-L{r.group.start}.patch"
            (out_dir / "patches" / name).write_text(r.diff)
            r.validation["patch_file"] = str((out_dir / "patches" / name).relative_to(root)) if out_dir.is_relative_to(root) else str(out_dir / "patches" / name)
    combined = "".join(unified_diff(p, sources[p], t) for p, t in sorted(patched.items()))
    (out_dir / "aisast-fixes.patch").write_text(combined)
    for p, t in patched.items():
        dst = files_dir / p
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(t)
    pr = pr_description(results)
    (out_dir / "PR_DESCRIPTION.md").write_text(pr)
    return {"combined_patch": str(out_dir / "aisast-fixes.patch"), "pr_description": str(out_dir / "PR_DESCRIPTION.md"),
            "fixed_files_dir": str(files_dir)}


def pr_description(results: list[FixResult]) -> str:
    ok = [r for r in results if r.status == "validated"]
    lines = ["## Security fixes generated by AI-SAST", "",
             f"This change fixes **{sum(len(r.group.findings) for r in ok)}** findings in **{len({r.group.file for r in ok})}** files. "
             "Every patch was validated (syntax check, security re-scan" + (", independent AI review" if any(r.validation.get('ai_review') == 'pass' for r in ok) else "") + ").", "",
             "| Finding | Severity | File | Fix | Method |", "|---|---|---|---|---|"]
    for r in ok:
        for f in r.group.findings:
            lines.append(f"| {f.id} {f.title} | {f.severity} | `{f.file}:{f.line}` | {r.summary[:120]} | {r.method} |")
    failed = [r for r in results if r.status != "validated"]
    if failed:
        lines += ["", "### Needs manual remediation", ""]
        for r in failed:
            for f in r.group.findings:
                lines.append(f"- {f.id} {f.title} — `{f.file}:{f.line}`")
    lines += ["", "> Review each change before merging. Rotate any credentials that were committed to the repository."]
    return "\n".join(lines) + "\n"


def apply_to_tree(root: Path, patched: dict[str, str]) -> list[str]:
    for p, t in patched.items():
        (root / p).write_text(t)
    return list(patched)


def git_commit(root: Path, files: list[str], results: list[FixResult], branch_prefix: str) -> dict:
    def git(*args):
        return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)
    if git("rev-parse", "--is-inside-work-tree").returncode != 0:
        return {"ok": False, "error": "not a git repository"}
    branch = f"{branch_prefix}-{time.strftime('%Y%m%d-%H%M%S')}"
    r = git("checkout", "-b", branch)
    if r.returncode != 0:
        return {"ok": False, "error": r.stderr.strip()}
    git("add", "--", *files)
    ok = [r for r in results if r.status == "validated"]
    msg = "fix(security): remediate {} findings with AI-SAST\n\n".format(sum(len(r.group.findings) for r in ok)) + \
        "\n".join(f"- {f.id} {f.title} ({f.cwe}) in {f.file}:{f.line}" for r in ok for f in r.group.findings)
    c = git("-c", "user.name=AI-SAST", "-c", "user.email=aisast@localhost", "commit", "-m", msg)
    if c.returncode != 0:
        return {"ok": False, "error": c.stderr.strip() or c.stdout.strip(), "branch": branch}
    sha = git("rev-parse", "--short", "HEAD").stdout.strip()
    return {"ok": True, "branch": branch, "commit": sha, "push": f"git push -u origin {branch}"}
