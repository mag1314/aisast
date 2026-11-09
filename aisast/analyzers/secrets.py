"""Secret detection for any text file: provider-specific token formats plus
entropy-checked generic assignments (config files, .env, JSON, YAML, JS...)."""
from __future__ import annotations

import math
import re
from collections import Counter

from ..models import Finding
from ..rules import meta

PROVIDER_PATTERNS = [
    ("SECRET-AWS-KEY", re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), "AWS access key id"),
    ("SECRET-AWS-KEY", re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][A-Za-z0-9/+=]{40}['\"]"), "AWS secret access key"),
    ("SECRET-PRIVATE-KEY", re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "Private key"),
    ("SECRET-GITHUB-TOKEN", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}\b"), "GitHub token"),
    ("SECRET-SLACK-TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "Slack token"),
    ("SECRET-STRIPE-KEY", re.compile(r"\b(sk|rk)_live_[A-Za-z0-9]{20,}\b"), "Stripe live secret key"),
]
GENERIC = re.compile(
    r"""(?ix)(?P<name>[\w.-]*(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret|token))
        ["']?\s*(?:=|:|=>)\s*["'](?P<val>[^"'\s]{8,})["']""")
ENVLINE = re.compile(r"(?i)^\s*(?:export\s+)?(?P<name>[A-Z0-9_]*(?:PASSWORD|SECRET|API_KEY|TOKEN|ACCESS_KEY|PRIVATE_KEY))\s*=\s*['\"]?(?P<val>[^'\"\s#]{8,})")
PLACEHOLDER = re.compile(r"(?i)^(x{4,}|\*{4,}|changeme|example\w*|your[-_].*|<.*>|\$\{.*\}|\{\{.*\}\}|process\.env.*|os\.environ.*|placeholder|dummy|test(ing)?|redacted|none|null)$")


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def scan_secrets(relpath: str, text: str, language: str, skip_generic: bool = False) -> list[Finding]:
    out, seen = [], set()
    lines = text.splitlines()
    is_env = relpath.rsplit("/", 1)[-1].startswith(".env") or relpath.endswith((".env", ".properties", ".ini", ".cfg"))
    for i, line in enumerate(lines, 1):
        if len(line) > 2000:
            continue
        for rule_id, rx, label in PROVIDER_PATTERNS:
            if rx.search(line) and (i, "p") not in seen:
                seen.add((i, "p"))
                out.append(_mk(rule_id, relpath, i, line, f"{label} committed to source code.", language, "high", "critical" if "PRIVATE" in rule_id or "AWS" in rule_id else "high"))
        if skip_generic or (i, "p") in seen:
            continue
        m = (ENVLINE.search(line) if is_env else None) or GENERIC.search(line)
        if m:
            val = m.group("val")
            if PLACEHOLDER.match(val) or re.fullmatch(r"[a-z_]+", val) or entropy(val) < 2.5:
                continue
            if "process.env" in line or "os.environ" in line or "getenv" in line:
                continue
            out.append(_mk("SECRET-GENERIC" if language not in ("javascript", "typescript") else "JS-HARDCODED-SECRET",
                           relpath, i, line, f"Hardcoded credential '{m.group('name')}'.", language,
                           "high" if entropy(val) > 3.5 else "medium", "high"))
    return out


def _mk(rule_id, relpath, line_no, line, message, language, confidence, severity):
    m = meta(rule_id)
    redacted = re.sub(r"([\"'=:]\s*[\"']?)([A-Za-z0-9/+_\-]{4})[A-Za-z0-9/+_\-]{6,}", r"\1\2********", line.strip())
    return Finding(rule_id=rule_id, title=m["title"], severity=severity, confidence=confidence, file=relpath,
                   line=line_no, message=message, cwe=m["cwe"], owasp=m["owasp"], category="secrets",
                   language=language, snippet=redacted[:200], engine="secrets")
