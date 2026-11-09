"""Scan orchestration: file discovery, deterministic analyzers, dedupe and scoring."""
from __future__ import annotations

import fnmatch
import os
import re
import time
from pathlib import Path

from .analyzers.javascript import scan_javascript
from .analyzers.python_taint import PythonTaintEngine
from .analyzers.secrets import scan_secrets
from .config import Config
from .models import Finding, SEVERITY_RANK, severity_at_least

LANGS = {".py": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
         ".ts": "typescript", ".tsx": "typescript", ".java": "java", ".go": "go", ".php": "php", ".rb": "ruby",
         ".cs": "csharp", ".c": "c", ".cpp": "cpp", ".kt": "kotlin", ".rs": "rust", ".swift": "swift", ".scala": "scala"}
TEXT_EXT = {".env", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties", ".xml", ".sh", ".txt",
            ".tf", ".dockerfile", ""}
TEST_PATH_RE = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?)/|(^|/)(test_[^/]+|[^/]+_test)\.py$|\.(spec|test)\.[jt]sx?$")
IGNORE_RE = re.compile(r"(#|//|/\*)\s*(aisast|nosec)[:\- ]?\s*ignore|#\s*nosec\b", re.I)


def language_of(path: Path) -> str:
    if path.name.startswith(".env"):
        return "config"
    return LANGS.get(path.suffix.lower(), "config" if path.suffix.lower() in TEXT_EXT else "")


def discover(root: Path, cfg: Config) -> list[Path]:
    out = []
    if root.is_file():
        return [root]
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not any(fnmatch.fnmatch(d, p) for p in cfg.excludes)]
        for fn in filenames:
            if any(fnmatch.fnmatch(fn, p) for p in cfg.excludes):
                continue
            p = Path(dirpath) / fn
            rel = p.relative_to(root).as_posix()
            if any(fnmatch.fnmatch(rel, p2) for p2 in cfg.excludes):
                continue
            if language_of(p) and p.stat().st_size <= cfg.max_file_kb * 1024:
                out.append(p)
    return sorted(out)


def rel(root: Path, p: Path) -> str:
    return p.name if root.is_file() else p.relative_to(root).as_posix()


def run_static(root: Path, cfg: Config, files: list[Path] | None = None) -> tuple[list[Finding], dict]:
    """Run all deterministic analyzers on files under root. Returns findings and stats."""
    files = files if files is not None else discover(root, cfg)
    sources: dict[str, str] = {}
    for p in files:
        try:
            sources[rel(root, p)] = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return scan_sources(sources, cfg)


def scan_sources(sources: dict[str, str], cfg: Config) -> tuple[list[Finding], dict]:
    """Run all deterministic analyzers on in-memory sources {relpath: text}."""
    t0 = time.time()
    py = PythonTaintEngine(strict=cfg.strict)
    findings: list[Finding] = []
    stats = {"files": 0, "lines": 0, "languages": {}, "parse_errors": []}
    for r, text in sources.items():
        lang = language_of(Path(r))
        stats["files"] += 1
        stats["lines"] += text.count("\n") + 1
        stats["languages"][lang] = stats["languages"].get(lang, 0) + 1
        if lang == "python":
            if not py.add_file(r, text):
                stats["parse_errors"].append(r)
        elif lang in ("javascript", "typescript"):
            findings += scan_javascript(r, text, lang, cfg.strict)
        findings += scan_secrets(r, text, lang, skip_generic=(lang == "python"))
    findings += py.analyze()
    findings = postprocess(findings, sources, cfg)
    stats["static_seconds"] = round(time.time() - t0, 3)
    return findings, stats


def postprocess(findings: list[Finding], sources: dict[str, str], cfg: Config) -> list[Finding]:
    out, seen = [], {}
    for f in findings:
        if TEST_PATH_RE.search(f.file) and f.category in ("secrets", "weak-crypto", "insecure-random", "tls", "debug") \
                and not f.rule_id.startswith(("SECRET-AWS", "SECRET-PRIVATE", "SECRET-GITHUB", "SECRET-SLACK", "SECRET-STRIPE")):
            continue  # fixture credentials / test-only crypto are not production weaknesses
        lines = sources.get(f.file, "").splitlines()
        if 0 < f.line <= len(lines) and (IGNORE_RE.search(lines[f.line - 1]) or (f.line > 1 and IGNORE_RE.search(lines[f.line - 2]) and lines[f.line - 2].strip().startswith(("#", "//")))):
            continue
        if not severity_at_least(f.severity, cfg.min_severity):
            continue
        key = (f.file, f.line, f.category)
        if key in seen:
            prev = seen[key]
            if (SEVERITY_RANK[f.severity], len(f.trace)) > (SEVERITY_RANK[prev.severity], len(prev.trace)):
                out[out.index(prev)] = f
                seen[key] = f
            continue
        seen[key] = f
        out.append(f)
    for f in out:
        f.compute_fingerprint()
        f.compute_risk()
    out.sort(key=lambda f: (-f.risk_score, f.file, f.line))
    return out


def read_sources(root: Path, cfg: Config) -> dict[str, str]:
    return {rel(root, p): p.read_text(encoding="utf-8", errors="replace") for p in discover(root, cfg)}
