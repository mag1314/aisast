"""Remediation tracking across scans (.aisast/state.json).

Each finding is keyed by its stable fingerprint. Status lifecycle:
open -> fix_proposed -> fixed -> verified   (verified = a later scan no longer sees it)
any active state -> reopened if it comes back; humans can set false_positive / accepted_risk.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

from .models import ACTIVE_STATUSES, STATUSES, Finding

HUMAN_STATES = {"false_positive", "accepted_risk"}


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def state_path(root: Path) -> Path:
    base = root if root.is_dir() else root.parent
    return base / ".aisast" / "state.json"


def load_state(root: Path) -> dict:
    p = state_path(root)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except json.JSONDecodeError:
            pass
    return {"findings": {}, "scans": []}


def save_state(root: Path, state: dict) -> None:
    p = state_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(state, indent=2))


def _event(rec: dict, status: str, actor: str, note: str = "") -> None:
    rec.setdefault("history", []).append({"at": now(), "status": status, "by": actor, **({"note": note} if note else {})})
    rec["status"] = status


def merge_scan(root: Path, findings: list[Finding], suppressed: list[Finding], scanned_files: set[str]) -> dict:
    state = load_state(root)
    recs = state["findings"]
    seen = set()
    summary = {"new": 0, "existing": 0, "reopened": 0, "resolved": 0, "resolved_ids": []}
    for f in findings + suppressed:
        seen.add(f.fingerprint)
        rec = recs.get(f.fingerprint)
        if rec is None:
            rec = {"id": f.id, "rule_id": f.rule_id, "title": f.title, "file": f.file, "severity": f.severity,
                   "first_seen": now(), "history": []}
            _event(rec, f.status, "ai-triage" if f.status == "false_positive" else "scanner")
            recs[f.fingerprint] = rec
            summary["new"] += 1
        else:
            summary["existing"] += 1
            prev = rec.get("status", "open")
            if prev in ("verified", "fixed"):
                _event(rec, "reopened", "scanner", "detected again after being fixed")
                summary["reopened"] += 1
            elif prev == "false_positive" and rec["history"] and rec["history"][-1]["by"] == "ai-triage" and f.status != "false_positive":
                _event(rec, "open", "ai-triage", "no longer classified as false positive")
            elif prev not in HUMAN_STATES and f.status == "false_positive" and prev != "false_positive":
                _event(rec, "false_positive", "ai-triage")
        rec.update({"line": f.line, "last_seen": now(), "severity": f.severity, "risk_score": f.risk_score})
        f.status = rec["status"]
        f.first_seen = rec.get("first_seen", "")
    for fp, rec in recs.items():
        if fp not in seen and rec.get("status") in ACTIVE_STATUSES and rec.get("file") in scanned_files:
            _event(rec, "verified", "scanner", "no longer detected")
            rec["resolved_at"] = now()
            summary["resolved"] += 1
            summary["resolved_ids"].append(rec["id"])
    counts = {s: 0 for s in STATUSES}
    for rec in recs.values():
        counts[rec.get("status", "open")] = counts.get(rec.get("status", "open"), 0) + 1
    summary["status_counts"] = counts
    state["scans"].append({"at": now(), "findings": len(findings), "suppressed": len(suppressed),
                           "new": summary["new"], "resolved": summary["resolved"]})
    state["scans"] = state["scans"][-50:]
    save_state(root, state)
    summary["history"] = state["scans"][-10:]
    return summary


def set_status(root: Path, ident: str, status: str, note: str = "", actor: str = "user",
               state: dict | None = None, save: bool = True) -> dict | None:
    if status not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)}")
    state = state or load_state(root)
    for fp, rec in state["findings"].items():
        if ident in (fp, rec.get("id")):
            _event(rec, status, actor, note)
            if save:
                save_state(root, state)
            return rec
    return None


def bulk_set(root: Path, ids: list[str], status: str, actor: str, note: str = "") -> None:
    state = load_state(root)
    for i in ids:
        set_status(root, i, status, note, actor, state=state, save=False)
    save_state(root, state)
