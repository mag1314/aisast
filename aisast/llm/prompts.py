"""Prompt templates and JSON schemas for the Ollama-backed stages."""

SEV_ENUM = ["critical", "high", "medium", "low", "info"]
CATEGORY_ENUM = ["sqli", "nosqli", "cmdi", "code-injection", "path-traversal", "ssrf", "xss", "ssti", "open-redirect",
                 "deserialization", "xxe", "secrets", "weak-crypto", "insecure-random", "debug", "tls", "jwt", "cookie",
                 "csrf", "idor", "missing-auth", "mass-assignment", "prototype-pollution", "insecure-temp", "xpathi",
                 "ldapi", "trust-boundary", "logic"]

SYSTEM_ANALYST = (
    "You are a senior application security engineer performing a code review. You are precise, "
    "skeptical and evidence driven: you only call something a vulnerability when attacker-controlled "
    "data can actually reach a dangerous operation (or a security control is genuinely missing), and you "
    "recognise sanitizers, allow-lists, parameterized queries and framework protections. "
    "Always answer with a single JSON object that matches the requested schema. No markdown."
)

TRIAGE_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["true_positive", "false_positive", "uncertain"]},
        "confidence": {"type": "number"},
        "severity": {"type": "string", "enum": SEV_ENUM},
        "explanation": {"type": "string"},
        "exploit_scenario": {"type": "string"},
        "root_cause": {"type": "string"},
        "remediation": {"type": "string"},
        "secure_example": {"type": "string"},
    },
    "required": ["verdict", "confidence", "severity", "explanation", "remediation"],
}

TRIAGE_PROMPT = """Review this static-analysis finding and decide whether it is a real, exploitable vulnerability.

Finding: {title} ({cwe}) — rule {rule_id}
Reported severity: {severity}   Detector confidence: {confidence}
Message: {message}
File: {file}, line {line} (marked with >>)
{trace_block}
Code:
```{language}
{code}
```
Module header (imports / constants):
```
{header}
```

Decide:
1. verdict: "true_positive" if attacker-influenced data can reach the sink or the weakness is real in this code;
   "false_positive" if the code is provably safe (constant data, effective sanitization/allow-list, parameterized API,
   test-only code); otherwise "uncertain".
2. confidence: 0.0-1.0 in your verdict.
3. severity: realistic severity in this context (critical/high/medium/low/info).
4. explanation: 2-4 sentences, specific to this code — what is wrong and why.
5. exploit_scenario: a concrete attack (example payload / request) if true_positive, else "".
6. root_cause: one sentence.
7. remediation: specific fix guidance for this code.
8. secure_example: a short corrected snippet for the marked line(s).
Return JSON only."""

DEEP_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "line": {"type": "integer"},
                    "category": {"type": "string", "enum": CATEGORY_ENUM},
                    "cwe": {"type": "string"},
                    "title": {"type": "string"},
                    "severity": {"type": "string", "enum": SEV_ENUM},
                    "confidence": {"type": "number"},
                    "evidence": {"type": "string"},
                    "description": {"type": "string"},
                },
                "required": ["line", "category", "cwe", "title", "severity", "confidence", "evidence", "description"],
            },
        }
    },
    "required": ["findings"],
}

DEEP_PROMPT = """Audit the following {language} code from `{file}` for security vulnerabilities.

Focus especially on flaws pattern-based scanners miss:
- broken access control: endpoints that read/modify an object by id without checking it belongs to the
  current user (IDOR, CWE-639); sensitive/admin endpoints with no authentication or role check (CWE-862)
- mass assignment of request data onto user/model objects (CWE-915)
- business-logic abuse: negative/zero amounts, missing limits, race conditions (use category "logic", CWE-840)
- insecure design of auth, sessions, tokens and crypto
Also report classic injection, deserialization, SSRF, path traversal, XSS and secrets if present.

Project security context (authentication / authorization helpers available in this codebase):
```
{security_context}
```

Already reported by the static analyzer (do NOT repeat these):
{known}

Code (line numbers on the left):
```{language}
{code}
```

Rules:
- Report only issues you can point to in THIS code. "line" must be the line number shown on the left where the
  issue manifests (e.g. the route/function line for missing checks, the sink line for injections).
- "evidence" must be copied verbatim from that line.
- Do not report style issues, missing input validation without impact, or hypothetical issues.
- If there is nothing new, return {{"findings": []}}.
Return JSON only."""

FIX_SCHEMA = {
    "type": "object",
    "properties": {
        "fixed_code": {"type": "string"},
        "new_imports": {"type": "array", "items": {"type": "string"}},
        "summary": {"type": "string"},
        "changes": {"type": "array", "items": {"type": "string"}},
        "breaking_change_risk": {"type": "string", "enum": ["none", "low", "medium", "high"]},
        "test_suggestion": {"type": "string"},
    },
    "required": ["fixed_code", "summary"],
}

FIX_PROMPT = """You are fixing security vulnerabilities in `{file}` ({language}).

Vulnerabilities to fix in the code below:
{vulns}

Module header (existing imports / constants):
```
{header}
```

Code to replace (lines {start}-{end}):
```{language}
{code}
```
{feedback}
Write a corrected version of exactly these lines.
Requirements:
- Fix every listed vulnerability with the idiomatic secure pattern (parameterized queries, argument lists without a
  shell, safe parsers, allow-lists, ownership/authorization checks using the project's existing helpers, escaping,
  secrets from environment variables, `secrets` module, etc.).
- Preserve the function's name, signature, decorators, return types and normal behaviour for legitimate input.
- Keep the original indentation. Do not include line numbers. Do not add unrelated refactors or comments that explain the attack.
- If a new import is needed, put the full import statement in "new_imports" (not in fixed_code).
Return JSON: fixed_code (the full replacement for lines {start}-{end}), new_imports, summary (one sentence),
changes (bullet list), breaking_change_risk, test_suggestion."""

REVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        "fixes_vulnerability": {"type": "boolean"},
        "preserves_behavior": {"type": "boolean"},
        "introduces_issues": {"type": "boolean"},
        "concerns": {"type": "string"},
    },
    "required": ["fixes_vulnerability", "preserves_behavior", "introduces_issues"],
}

REVIEW_PROMPT = """Review a proposed security patch.

Vulnerabilities it must fix:
{vulns}

Original code:
```{language}
{original}
```

Patched code:
```{language}
{patched}
```
New imports: {imports}

Answer: does the patch fully fix the vulnerabilities (fixes_vulnerability)? Does it preserve behaviour for
legitimate inputs (preserves_behavior)? Does it introduce new bugs or vulnerabilities (introduces_issues)?
concerns: short text. Return JSON only."""

ASK_PROMPT = """A developer has a question about this security finding.

Finding: {title} ({cwe}) in {file}:{line} — {message}
{trace_block}
Code:
```{language}
{code}
```
Previous analysis: {analysis}

Question: {question}

Answer clearly and concretely in JSON: {{"answer": "..."}}"""

SUMMARY_PROMPT = """You are writing the executive summary of a security assessment.

Scan statistics: {stats}
Top findings (id | severity | title | file:line):
{top}

Write JSON with:
- "executive_summary": 3-5 sentences for engineering leadership: overall risk posture, the most important problems, and what to do first.
- "key_risks": array of 3-5 short strings.
- "recommended_actions": array of 3-6 prioritized, concrete actions.
Return JSON only."""
