"""Code-context helpers shared by triage, deep scan and remediation: find the
enclosing function/statement for a line, render numbered snippets, and summarize
project-level security context (auth decorators / middleware) for the LLM."""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass


@dataclass
class Region:
    start: int   # 1-based inclusive
    end: int     # 1-based inclusive
    kind: str    # function | statement | window
    name: str = ""


def python_region(source: str, line: int) -> Region | None:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    best = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line <= (node.end_lineno or node.lineno):
            start = min([d.lineno for d in node.decorator_list] + [node.lineno])
            if best is None or start >= best.start:
                best = Region(start, node.end_lineno or node.lineno, "function", node.name)
    if best:
        return best
    for node in tree.body:  # module-level statement
        if node.lineno <= line <= (node.end_lineno or node.lineno):
            # a top-level `if __name__ == ...` block: narrow to the inner statement
            if isinstance(node, ast.If):
                for inner in node.body:
                    if inner.lineno <= line <= (inner.end_lineno or inner.lineno):
                        return Region(inner.lineno, inner.end_lineno or inner.lineno, "statement")
            return Region(node.lineno, node.end_lineno or node.lineno, "statement")
    return None


FUNC_START = re.compile(r"(function\b[^(]*\(|=>\s*\{|\b(app|router)\.(get|post|put|delete|patch|all|use)\s*\(|^\s*(async\s+)?[\w$]+\s*\([^)]*\)\s*\{)")


def brace_region(lines: list[str], line: int) -> Region | None:
    """Find the enclosing top-level-ish block for C-like languages (JS/TS/Java/Go...)."""
    for start in range(line - 1, max(-1, line - 80), -1):
        text = lines[start]
        if FUNC_START.search(text) and (start == 0 or not lines[start].startswith((" ", "\t")) or start >= line - 40):
            depth, opened = 0, False
            for end in range(start, min(len(lines), start + 200)):
                code = re.sub(r"(['\"`]).*?\1", "", lines[end])
                depth += code.count("{") - code.count("}")
                opened = opened or "{" in code
                if opened and depth <= 0 and end + 1 >= line:
                    if lines[start].lstrip() == lines[start] or end - start < 60:
                        return Region(start + 1, end + 1, "function")
                    break
            break
    return None


def region_for(source: str, line: int, language: str) -> Region:
    lines = source.splitlines()
    r = None
    if language == "python":
        r = python_region(source, line)
    elif language in ("javascript", "typescript", "java", "go", "csharp", "php", "c", "cpp", "kotlin", "rust", "scala", "swift"):
        r = brace_region(lines, line)
    if r is None or r.end - r.start > 120:
        r = Region(max(1, line - 2), min(len(lines), line + 2), "window") if language not in ("config", "") else Region(line, line, "statement")
    return r


def numbered(source: str, start: int, end: int, mark: set[int] | None = None) -> str:
    lines = source.splitlines()
    out = []
    for i in range(max(1, start), min(len(lines), end) + 1):
        flag = ">>" if mark and i in mark else "  "
        out.append(f"{flag}{i:5d} | {lines[i - 1]}")
    return "\n".join(out)


def context_window(source: str, line: int, language: str, pad: int = 6) -> tuple[str, Region]:
    r = region_for(source, line, language)
    return numbered(source, max(1, r.start - pad if r.kind == "window" else r.start),
                    r.end + (pad if r.kind == "window" else 0), {line}), r


def file_header(source: str, max_lines: int = 30) -> str:
    """Imports and module constants: lets the model know what's available."""
    lines = source.splitlines()
    keep = [l for l in lines[:120] if re.match(r"\s*(import |from \S+ import|const \w+ = require|import\s|[A-Z_]{3,}\s*=|require\()", l)]
    return "\n".join(keep[:max_lines])


AUTH_HINT = re.compile(r"(login_required|admin_required|auth|permission|role|requires?_\w+|is_admin|ensure\w*|verify\w*Token|authenticate)", re.I)


def project_security_context(sources: dict[str, str], max_chars: int = 2500) -> str:
    """Summarize authentication/authorization helpers so the model can reason about
    missing auth and IDOR across routes."""
    parts = []
    for path, src in sources.items():
        if path.endswith(".py"):
            try:
                tree = ast.parse(src)
            except SyntaxError:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef) and AUTH_HINT.search(node.name):
                    seg = "\n".join(src.splitlines()[node.lineno - 1:min(node.end_lineno or node.lineno, node.lineno + 12)])
                    parts.append(f"# {path}:{node.lineno}\n{seg}")
        elif path.endswith((".js", ".ts")):
            for m in re.finditer(r"(function\s+(\w*(auth|Auth|require|verify)\w*)\s*\([^)]*\)\s*\{[^}]{0,400}\})", src):
                parts.append(f"// {path}\n{m.group(1)}")
    text = "\n\n".join(parts)
    return text[:max_chars] if text else "(no authentication/authorization helpers were found in the project)"
