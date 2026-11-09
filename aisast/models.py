"""Core data model: findings, severities and stable fingerprints."""
from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEVERITY_RANK = {s: i for i, s in enumerate(reversed(SEVERITIES))}  # info=0 … critical=4
SEVERITY_BASE = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.5}
CONFIDENCE_FACTOR = {"high": 1.0, "medium": 0.85, "low": 0.65}

# Remediation / triage lifecycle
STATUSES = [
    "open",              # detected, not yet addressed
    "fix_proposed",      # an AI/template patch was generated and validated
    "fixed",             # patch applied to the working tree
    "verified",          # a later scan confirmed the issue is gone
    "reopened",          # previously fixed/verified but detected again
    "false_positive",    # dismissed (by AI triage or a human)
    "accepted_risk",     # known and accepted by a human
]
ACTIVE_STATUSES = {"open", "fix_proposed", "fixed", "reopened"}


def severity_at_least(sev: str, minimum: str) -> bool:
    return SEVERITY_RANK.get(sev, 0) >= SEVERITY_RANK.get(minimum, 0)


def shift_severity(sev: str, delta: int) -> str:
    rank = max(0, min(4, SEVERITY_RANK.get(sev, 2) + delta))
    return {v: k for k, v in SEVERITY_RANK.items()}[rank]


def _normalize(code: str) -> str:
    return re.sub(r"\s+", " ", code).strip()


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    confidence: str
    file: str              # path relative to the scan root, posix style
    line: int
    message: str
    cwe: str = ""
    owasp: str = ""
    category: str = ""
    language: str = ""
    end_line: int = 0
    column: int = 0
    snippet: str = ""
    engine: str = "rule"   # rule | taint | secrets | llm
    function: str = ""     # enclosing function, when known
    trace: list = field(default_factory=list)   # taint path, human readable steps
    risk_score: float = 0.0
    priority: str = ""
    fingerprint: str = ""
    id: str = ""
    status: str = "open"
    first_seen: str = ""
    ai: dict = field(default_factory=dict)       # triage / explanation output
    fix: dict = field(default_factory=dict)      # remediation output
    extra: dict = field(default_factory=dict)

    def compute_fingerprint(self) -> str:
        """Stable across line shifts: rule + file + function + normalized code line."""
        basis = "|".join([self.rule_id, self.file, self.function, _normalize(self.snippet.splitlines()[0] if self.snippet else "")])
        self.fingerprint = hashlib.sha1(basis.encode()).hexdigest()[:16]
        self.id = "AIS-" + self.fingerprint[:8].upper()
        return self.fingerprint

    def compute_risk(self) -> float:
        score = SEVERITY_BASE.get(self.severity, 5.0) * CONFIDENCE_FACTOR.get(self.confidence, 0.85)
        if self.trace and any("remote" in str(t).lower() or "request" in str(t).lower() for t in self.trace):
            score += 0.5          # attacker-controlled data proven to reach the sink
        if self.extra.get("route"):
            score += 0.3          # reachable from an HTTP handler
        self.risk_score = round(min(10.0, score), 1)
        self.priority = "P1" if self.risk_score >= 8.5 else "P2" if self.risk_score >= 6.5 else "P3" if self.risk_score >= 4 else "P4"
        return self.risk_score

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class ScanResult:
    root: str
    findings: list
    suppressed: list            # false positives / filtered
    stats: dict
    started: str
    finished: str
    ai: dict = field(default_factory=dict)
    tracking: dict = field(default_factory=dict)
    version: str = ""

    def to_dict(self) -> dict:
        return {
            "tool": "aisast", "version": self.version, "root": self.root,
            "started": self.started, "finished": self.finished,
            "stats": self.stats, "ai": self.ai, "tracking": self.tracking,
            "findings": [f.to_dict() for f in self.findings],
            "suppressed": [f.to_dict() for f in self.suppressed],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScanResult":
        return cls(root=d["root"], findings=[Finding.from_dict(x) for x in d.get("findings", [])],
                   suppressed=[Finding.from_dict(x) for x in d.get("suppressed", [])],
                   stats=d.get("stats", {}), started=d.get("started", ""), finished=d.get("finished", ""),
                   ai=d.get("ai", {}), tracking=d.get("tracking", {}), version=d.get("version", ""))


def best(items: Optional[list], default=None):
    return items[0] if items else default
