"""Configuration: defaults <- aisast.toml (project root or --config) <- environment <- CLI flags."""
from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_EXCLUDES = [
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env", "__pycache__", "dist", "build",
    ".aisast", ".tox", ".mypy_cache", ".pytest_cache", "site-packages", "vendor", "*.min.js", "coverage",
]


@dataclass
class Config:
    # --- Ollama / LLM
    ollama_url: str = "http://localhost:11434"
    model: str = "qwen2.5-coder:7b"
    fix_model: str = ""                 # optional bigger model for remediation; defaults to `model`
    temperature: float = 0.1
    num_ctx: int = 8192
    timeout: int = 300
    ai_enabled: bool = True
    deep_scan: bool = False             # LLM discovery pass over files (finds logic flaws rules can't)
    triage: bool = True                 # LLM verifies / explains rule findings
    fp_threshold: float = 0.75          # AI false-positive confidence needed to suppress a finding
    max_ai_findings: int = 200
    deep_scan_max_files: int = 60
    cache: bool = True
    # --- scanning
    excludes: list = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    max_file_kb: int = 512
    strict: bool = False                # report every weak-crypto / PRNG usage, not only security contexts
    min_severity: str = "info"
    # --- remediation
    fix_attempts: int = 3
    fix_min_severity: str = "low"
    test_command: str = ""
    git_branch_prefix: str = "aisast/fix"
    # --- reporting
    formats: list = field(default_factory=lambda: ["html", "json", "sarif", "md"])
    output_dir: str = ".aisast/reports"

    @property
    def remediation_model(self) -> str:
        return self.fix_model or self.model


def load_config(root: Path, explicit: str | None = None) -> Config:
    cfg = Config()
    path = Path(explicit) if explicit else root / "aisast.toml"
    if path.is_file():
        data = tomllib.loads(path.read_text())
        flat = {}
        for section in ("ollama", "scan", "fix", "report", "ai"):
            flat.update(data.get(section, {}))
        flat.update({k: v for k, v in data.items() if not isinstance(v, dict)})
        aliases = {"url": "ollama_url", "exclude": "excludes", "format": "formats"}
        for k, v in flat.items():
            k = aliases.get(k, k)
            if hasattr(cfg, k):
                if k == "excludes" and isinstance(v, list):
                    v = list(DEFAULT_EXCLUDES) + v
                setattr(cfg, k, v)
    env = {"OLLAMA_HOST": "ollama_url", "AISAST_MODEL": "model", "AISAST_FIX_MODEL": "fix_model"}
    for var, attr in env.items():
        if os.environ.get(var):
            val = os.environ[var]
            if attr == "ollama_url" and not val.startswith("http"):
                val = "http://" + val
            setattr(cfg, attr, val)
    return cfg
