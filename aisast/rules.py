"""Rule catalog. Every finding references a rule id from here (LLM findings use AI-<category>)."""
from __future__ import annotations

OWASP = {
    "A01": "A01:2021 Broken Access Control",
    "A02": "A02:2021 Cryptographic Failures",
    "A03": "A03:2021 Injection",
    "A04": "A04:2021 Insecure Design",
    "A05": "A05:2021 Security Misconfiguration",
    "A07": "A07:2021 Identification and Authentication Failures",
    "A08": "A08:2021 Software and Data Integrity Failures",
    "A10": "A10:2021 Server-Side Request Forgery",
}

# category -> (title, cwe, owasp, default severity, guidance)
CATEGORIES = {
    "sqli": ("SQL Injection", "CWE-89", "A03", "critical",
             "Use parameterized queries / bound parameters; never build SQL with string formatting."),
    "nosqli": ("NoSQL Injection", "CWE-943", "A03", "high",
               "Validate types of user input and never pass raw request objects into query filters."),
    "cmdi": ("OS Command Injection", "CWE-78", "A03", "critical",
             "Avoid the shell: pass an argument list to subprocess with shell=False and validate inputs."),
    "code-injection": ("Code Injection", "CWE-94", "A03", "critical",
                       "Never evaluate user input as code. Use ast.literal_eval / JSON parsing or a safe expression parser."),
    "path-traversal": ("Path Traversal", "CWE-22", "A01", "high",
                       "Normalize the path, strip directories (basename/secure_filename) and verify it stays inside the allowed base directory."),
    "ssrf": ("Server-Side Request Forgery", "CWE-918", "A10", "high",
             "Allow-list destination hosts/schemes and block internal address ranges before fetching user-supplied URLs."),
    "xss": ("Cross-Site Scripting", "CWE-79", "A03", "high",
            "Escape output (html.escape / templating auto-escape) or build responses with safe templates."),
    "ssti": ("Server-Side Template Injection", "CWE-1336", "A03", "critical",
             "Never compile user input as a template; pass it as a variable to a static template."),
    "open-redirect": ("Open Redirect", "CWE-601", "A01", "medium",
                      "Only redirect to relative paths or allow-listed hosts."),
    "deserialization": ("Insecure Deserialization", "CWE-502", "A08", "critical",
                        "Do not deserialize untrusted data with pickle/yaml.load/node-serialize; use JSON or yaml.safe_load."),
    "xxe": ("XML External Entity Injection", "CWE-611", "A05", "high",
            "Disable DTDs and external entity resolution (defusedxml, resolve_entities=False)."),
    "secrets": ("Hardcoded Secret", "CWE-798", "A07", "high",
                "Move secrets to environment variables or a secret manager and rotate the exposed credential."),
    "weak-crypto": ("Weak Cryptographic Hash", "CWE-327", "A02", "medium",
                    "Use a password hashing function (bcrypt/scrypt/argon2/PBKDF2) or SHA-256+ for integrity."),
    "insecure-random": ("Insecure Randomness", "CWE-330", "A02", "medium",
                        "Use the secrets module (Python) or crypto.randomBytes (Node) for security tokens."),
    "debug": ("Debug Mode Enabled", "CWE-489", "A05", "medium",
              "Disable debug mode in production; drive it from configuration."),
    "tls": ("TLS Certificate Validation Disabled", "CWE-295", "A02", "medium",
            "Keep certificate verification enabled (verify=True / rejectUnauthorized)."),
    "jwt": ("JWT Signature Not Verified", "CWE-347", "A07", "high",
            "Always verify JWT signatures with an explicit algorithm allow-list."),
    "cookie": ("Insecure Cookie", "CWE-614", "A05", "low",
               "Set Secure, HttpOnly and SameSite attributes on session cookies."),
    "csrf": ("CSRF Protection Disabled", "CWE-352", "A01", "medium",
             "Keep CSRF protection enabled for state-changing requests."),
    "idor": ("Insecure Direct Object Reference", "CWE-639", "A01", "high",
             "Check that the authenticated user owns or may access the requested object."),
    "missing-auth": ("Missing Authorization", "CWE-862", "A01", "high",
                     "Require authentication and role checks on sensitive endpoints."),
    "mass-assignment": ("Mass Assignment", "CWE-915", "A04", "medium",
                        "Copy only allow-listed fields from request data onto models."),
    "prototype-pollution": ("Prototype Pollution", "CWE-1321", "A08", "high",
                            "Reject __proto__/constructor keys or use Object.create(null) / safe merge helpers."),
    "insecure-temp": ("Insecure Temporary File", "CWE-377", "A05", "low",
                      "Use tempfile.mkstemp / NamedTemporaryFile instead of mktemp."),
    "xpathi": ("XPath Injection", "CWE-643", "A03", "high",
               "Use parameterized XPath (variables such as $name) instead of building expressions from input."),
    "ldapi": ("LDAP Injection", "CWE-90", "A03", "high",
              "Escape filter values (ldap3.utils.conv.escape_filter_chars) or validate them against an allow-list."),
    "trust-boundary": ("Trust Boundary Violation", "CWE-501", "A04", "medium",
                       "Validate data before storing it in trusted server-side state such as the session."),
    "logic": ("Security Logic Flaw", "CWE-840", "A04", "medium",
              "Review the business logic for abuse cases."),
    "other": ("Security Weakness", "CWE-693", "A04", "medium", "Review and harden this code."),
}

# rule_id -> category ; titles are derived from the category unless overridden
RULES = {
    "PY-SQLI-TAINT": "sqli", "PY-SQLI-FORMAT": "sqli",
    "PY-CMDI-TAINT": "cmdi", "PY-CMDI-SHELL": "cmdi",
    "PY-CODE-EVAL": "code-injection",
    "PY-PATH-TRAVERSAL": "path-traversal",
    "PY-SSRF": "ssrf",
    "PY-XSS-RESPONSE": "xss",
    "PY-SSTI": "ssti",
    "PY-OPEN-REDIRECT": "open-redirect",
    "PY-DESER-PICKLE": "deserialization", "PY-DESER-YAML": "deserialization",
    "PY-XXE": "xxe",
    "PY-WEAK-HASH": "weak-crypto",
    "PY-INSECURE-RANDOM": "insecure-random",
    "PY-FLASK-DEBUG": "debug",
    "PY-TLS-VERIFY": "tls",
    "PY-JWT-NOVERIFY": "jwt",
    "PY-COOKIE-INSECURE": "cookie",
    "PY-CSRF-DISABLED": "csrf",
    "PY-TEMPFILE": "insecure-temp",
    "PY-HARDCODED-SECRET": "secrets",
    "PY-XPATH-INJECTION": "xpathi", "PY-LDAP-INJECTION": "ldapi", "PY-TRUST-BOUNDARY": "trust-boundary",
    "JS-SQLI": "sqli", "JS-NOSQLI": "nosqli", "JS-CMDI": "cmdi", "JS-CODE-EVAL": "code-injection",
    "JS-PATH-TRAVERSAL": "path-traversal", "JS-SSRF": "ssrf", "JS-XSS": "xss", "JS-DOM-XSS": "xss",
    "JS-OPEN-REDIRECT": "open-redirect", "JS-DESER": "deserialization", "JS-WEAK-HASH": "weak-crypto",
    "JS-INSECURE-RANDOM": "insecure-random", "JS-JWT-NOVERIFY": "jwt", "JS-TLS-VERIFY": "tls",
    "JS-PROTO-POLLUTION": "prototype-pollution", "JS-HARDCODED-SECRET": "secrets",
    "SECRET-AWS-KEY": "secrets", "SECRET-PRIVATE-KEY": "secrets", "SECRET-GITHUB-TOKEN": "secrets",
    "SECRET-SLACK-TOKEN": "secrets", "SECRET-STRIPE-KEY": "secrets", "SECRET-GENERIC": "secrets",
}


def meta(rule_id: str) -> dict:
    cat = RULES.get(rule_id) or (rule_id[3:].lower() if rule_id.startswith("AI-") else "other")
    if cat not in CATEGORIES:
        cat = "other"
    title, cwe, owasp, sev, guidance = CATEGORIES[cat]
    return {"rule_id": rule_id, "category": cat, "title": title, "cwe": cwe,
            "owasp": OWASP.get(owasp, owasp), "severity": sev, "guidance": guidance}


def category_for_cwe(cwe: str) -> str:
    cwe = (cwe or "").upper().replace(" ", "")
    for cat, (_, c, *_rest) in CATEGORIES.items():
        if c == cwe:
            return cat
    aliases = {"CWE-284": "missing-auth", "CWE-285": "missing-auth", "CWE-306": "missing-auth", "CWE-863": "missing-auth",
               "CWE-200": "other", "CWE-1333": "other", "CWE-80": "xss", "CWE-77": "cmdi", "CWE-95": "code-injection",
               "CWE-96": "ssti", "CWE-328": "weak-crypto", "CWE-916": "weak-crypto", "CWE-338": "insecure-random",
               "CWE-23": "path-traversal", "CWE-36": "path-traversal", "CWE-798": "secrets", "CWE-259": "secrets",
               "CWE-943": "nosqli", "CWE-1321": "prototype-pollution", "CWE-915": "mass-assignment",
               "CWE-345": "jwt", "CWE-287": "missing-auth", "CWE-352": "csrf", "CWE-601": "open-redirect",
               "CWE-639": "idor", "CWE-643": "xpathi", "CWE-90": "ldapi", "CWE-501": "trust-boundary", "CWE-614": "cookie", "CWE-1004": "cookie", "CWE-862": "missing-auth", "CWE-489": "debug", "CWE-215": "debug", "CWE-94": "code-injection"}
    return aliases.get(cwe, "other")


def all_rules() -> list[dict]:
    return [meta(r) for r in sorted(RULES)]
