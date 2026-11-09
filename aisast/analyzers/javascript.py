"""JavaScript / TypeScript analyzer.

A dependency-free "flow-lite" analyzer: comments are stripped (string aware), variable
assignments are processed in order to propagate taint from request sources
(req.query/body/params/headers/cookies, location.*, process.argv), and sink calls are
extracted with balanced-parenthesis matching so multi-line calls are handled.
It is deliberately lighter than the Python engine; the LLM deep-scan complements it.
"""
from __future__ import annotations

import re

from ..models import Finding
from ..rules import meta

SOURCE_RE = re.compile(r"\b(?:req|request|ctx\.request)\.(query|body|params|headers|cookies|files)\b|"
                       r"\b(?:location\.(?:hash|search|href)|document\.(?:URL|cookie|referrer)|window\.name|process\.argv)\b")
SANITIZER_RE = re.compile(r"^\s*(?:await\s+)?(parseInt|parseFloat|Number|Boolean|encodeURIComponent|encodeURI|escapeHtml|escape|"
                          r"he\.encode|validator\.\w+|path\.basename|sanitize\w*|DOMPurify\.sanitize|xss|mysql\.escape|"
                          r"connection\.escape|String\(Number|Math\.\w+|uuidValidate|isValid\w*)\s*\(")
SEC_WORDS = re.compile(r"(?i)token|password|passwd|secret|otp|nonce|salt|session|reset|apikey|api_key|auth|sign")
ASSIGN_RE = re.compile(r"^\s*(?:export\s+)?(?:const|let|var)?\s*(?P<lhs>\{[^}]*\}|\[[^\]]*\]|[A-Za-z_$][\w$.]*)\s*(?P<op>=|\+=)(?!=|>)\s*(?P<rhs>.+)$")


def strip_comments(src: str) -> str:
    out, i, n = [], 0, len(src)
    state = None  # None | quote char | 'line' | 'block'
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if state is None:
            if c in "'\"`":
                state = c
                out.append(c)
            elif c == "/" and nxt == "/":
                state = "line"; out.append("  "); i += 1
            elif c == "/" and nxt == "*":
                state = "block"; out.append("  "); i += 1
            else:
                out.append(c)
        elif state == "line":
            if c == "\n":
                state = None; out.append(c)
            else:
                out.append(" ")
        elif state == "block":
            if c == "*" and nxt == "/":
                state = None; out.append("  "); i += 1
            else:
                out.append("\n" if c == "\n" else " ")
        else:  # inside string
            out.append(c)
            if c == "\\" and nxt:
                out.append(nxt); i += 1
            elif c == state:
                state = None
        i += 1
    return "".join(out)


SANITIZER_CALL_RE = re.compile(r"(?<![\w$.])(parseInt|parseFloat|Number|encodeURIComponent|escapeHtml|escape|he\.encode|"
                               r"validator\.\w+|path\.basename|sanitize\w*|DOMPurify\.sanitize|xss|mysql\.escape|"
                               r"connection\.escape|db\.escape)\s*\(")


def strip_sanitized(expr: str) -> str:
    """Remove sanitizer calls (and their arguments) from an expression."""
    for _ in range(10):
        m = SANITIZER_CALL_RE.search(expr)
        if not m:
            break
        inner = call_args(expr, m.end() - 1)
        expr = expr[:m.start()] + "0" + expr[m.end() + len(inner) + 1:]
    return expr


def call_args(text: str, open_idx: int) -> str:
    """Return the text between the parenthesis at open_idx and its match."""
    depth, i, q = 0, open_idx, None
    while i < len(text):
        c = text[i]
        if q:
            if c == "\\":
                i += 2; continue
            if c == q:
                q = None
        elif c in "'\"`":
            q = c
        elif c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1:i]
        i += 1
    return text[open_idx + 1:open_idx + 400]


def split_top_args(args: str) -> list[str]:
    parts, depth, cur, q = [], 0, [], None
    i = 0
    while i < len(args):
        c = args[i]
        if q:
            cur.append(c)
            if c == "\\" and i + 1 < len(args):
                cur.append(args[i + 1]); i += 1
            elif c == q:
                q = None
        elif c in "'\"`":
            q = c; cur.append(c)
        elif c in "([{":
            depth += 1; cur.append(c)
        elif c in ")]}":
            depth -= 1; cur.append(c)
        elif c == "," and depth == 0:
            parts.append("".join(cur).strip()); cur = []
        else:
            cur.append(c)
        i += 1
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


SINKS = [
    # (rule, regex for call head ending with "(", which arg, kind)
    ("JS-CODE-EVAL", re.compile(r"(?<![\w.$])(eval|new\s+Function|vm\.runIn\w+Context|vm\.runInThisContext)\s*\("), 0, "code"),
    ("JS-CODE-EVAL", re.compile(r"(?<![\w.$])(setTimeout|setInterval)\s*\("), 0, "code-str"),
    ("JS-CMDI", re.compile(r"(?<![\w$])(?:child_process\.|cp\.)?(exec|execSync)\s*\("), 0, "cmd"),
    ("JS-CMDI", re.compile(r"(?<![\w$])(?:child_process\.|cp\.)?(spawn|spawnSync)\s*\("), 0, "spawn"),
    ("JS-SQLI", re.compile(r"\.(query|raw|execute|exec\w*Raw\w*|\$queryRawUnsafe|\$executeRawUnsafe)\s*\("), 0, "sql"),
    ("JS-NOSQLI", re.compile(r"\.(find|findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|countDocuments|where)\s*\("), 0, "nosql"),
    ("JS-XSS", re.compile(r"\bres\.(send|write|end)\s*\("), 0, "xss"),
    ("JS-DOM-XSS", re.compile(r"(?<![\w$])(document\.write|document\.writeln|\.insertAdjacentHTML)\s*\("), -1, "dom"),
    ("JS-PATH-TRAVERSAL", re.compile(r"(?<![\w$])(?:fs\.|fsp\.|fs\.promises\.)(readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync|readdir|rm|rmSync)\s*\("), 0, "path"),
    ("JS-PATH-TRAVERSAL", re.compile(r"\bres\.(sendFile|download)\s*\("), 0, "path"),
    ("JS-SSRF", re.compile(r"(?<![\w$.])(axios(?:\.(?:get|post|put|delete|request))?|fetch|got|needle|request|https?\.get|https?\.request)\s*\("), 0, "ssrf"),
    ("JS-OPEN-REDIRECT", re.compile(r"\bres\.redirect\s*\("), -1, "redirect"),
    ("JS-DESER", re.compile(r"(?<![\w$])(?:serialize\.)?unserialize\s*\("), 0, "deser"),
    ("JS-PROTO-POLLUTION", re.compile(r"(?<![\w$])(?:_\.|lodash\.)?(merge|mergeWith|defaultsDeep|deepMerge|extend|deepExtend|setWith|set)\s*\("), -1, "proto"),
]
INNER_HTML = re.compile(r"\.(innerHTML|outerHTML)\s*(?:\+)?=\s*(.+)")


class JSAnalyzer:
    def __init__(self, relpath: str, source: str, language: str = "javascript", strict: bool = False):
        self.relpath, self.raw, self.language, self.strict = relpath, source, language, strict
        self.code = strip_comments(source)
        self.lines = self.code.split("\n")
        self.raw_lines = source.split("\n")
        self.env: dict[str, list] = {}   # var -> trace
        self.findings: list[Finding] = []
        self.offsets = []
        pos = 0
        for ln in self.lines:
            self.offsets.append(pos)
            pos += len(ln) + 1

    # --- taint helpers
    def taint_of(self, expr: str):
        expr = strip_sanitized(expr.strip())
        if not expr or SANITIZER_RE.match(expr):
            return None
        m = SOURCE_RE.search(expr)
        if m:
            return [f"remote input: {m.group(0)}"]
        for name, trace in self.env.items():
            if re.search(r"(?<![\w$.])" + re.escape(name) + r"(?![\w$])", expr):
                return trace
        return None

    def is_constant(self, expr: str) -> bool:
        e = expr.strip()
        if re.fullmatch(r"'[^']*'|\"[^\"]*\"|`[^`$]*`|\d+", e):
            return True
        return bool(re.fullmatch(r"[A-Z_][A-Z0-9_]*", e))

    def line_of(self, idx: int) -> int:
        lo, hi = 0, len(self.offsets) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.offsets[mid] <= idx:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    # --- main loop
    def analyze(self) -> list[Finding]:
        for i, line in enumerate(self.lines, 1):
            self.track_assignment(line, i)
            self.check_sinks(line, i)
            self.check_patterns(line, i)
        return self.findings

    def track_assignment(self, line: str, ln: int):
        m = ASSIGN_RE.match(line)
        if not m:
            return
        lhs, rhs = m.group("lhs"), m.group("rhs")
        # include continuation lines for multi-line expressions
        if rhs.count("(") > rhs.count(")") or rhs.rstrip().endswith(("+", "`")):
            rhs = call_args("(" + "\n".join(self.lines[ln - 1:ln + 6]).split(m.group("op"), 1)[1] + ")", 0)
        t = self.taint_of(rhs)
        names = re.findall(r"[A-Za-z_$][\w$]*", lhs.split(":")[-1] if lhs.startswith("{") and ":" in lhs else lhs) \
            if lhs.startswith(("{", "[")) else [lhs]
        if lhs.startswith("{"):
            names = [p.split(":")[-1].split("=")[0].strip() for p in lhs.strip("{} ").split(",") if p.strip()]
        for name in names:
            if t:
                self.env[name] = (t + [f"{self.relpath}:{ln}: {line.strip()[:90]}"])[-8:]
            elif m.group("op") == "=" and name in self.env:
                del self.env[name]  # strong update: re-assigned with clean data

    def check_sinks(self, line: str, ln: int):
        for rule, rx, argi, kind in SINKS:
            for mm in rx.finditer(line):
                start = self.offsets[ln - 1] + mm.end() - 1
                args = split_top_args(call_args(self.code, start))
                if not args:
                    continue
                arg = args[argi] if -len(args) <= argi < len(args) else args[0]
                self.eval_sink(rule, kind, arg, args, line, ln)
        m = INNER_HTML.search(line)
        if m:
            t = self.taint_of(m.group(2))
            if t:
                self.add("JS-DOM-XSS", ln, "Untrusted data assigned to innerHTML.", t, "high")

    def eval_sink(self, rule, kind, arg, args, line, ln):
        t = self.taint_of(arg)
        building = "${" in arg or re.search(r"['\"`]\s*\+|\+\s*['\"`]", arg) is not None
        if kind == "code":
            if t:
                return self.add(rule, ln, "User-controlled data is evaluated as code.", t, "high")
            if not self.is_constant(arg):
                return self.add(rule, ln, "Dynamic code evaluation of a non-constant value.", None, "low", "medium")
        elif kind == "code-str":
            if t and (arg.strip().startswith(("'", '"', "`")) or building):
                return self.add(rule, ln, "String passed to timer is evaluated as code.", t, "high")
        elif kind == "cmd":
            if t:
                return self.add(rule, ln, "User-controlled data reaches a shell command.", t, "high")
            if building:
                return self.add(rule, ln, "Shell command built from non-constant values.", None, "low", "medium")
        elif kind == "spawn":
            shell = any(re.search(r"shell\s*:\s*true", a) for a in args)
            if t and shell:
                return self.add(rule, ln, "User-controlled data reaches spawn() with shell:true.", t, "high")
        elif kind == "sql":
            if t and building:
                return self.add(rule, ln, "User-controlled data concatenated into a SQL query.", t, "high")
            if t and not arg.strip().startswith(("'", '"', "`")):
                if self._var_is_built(arg.strip()):
                    return self.add(rule, ln, "User-controlled data concatenated into a SQL query.", t, "high")
            if building and not t and re.search(r"\$\{(?!\s*[A-Z_]+\s*\})|\+\s*[a-z]", arg) and re.search(r"(?i)select|insert|update|delete", arg):
                return self.add(rule, ln, "SQL built from non-constant values.", None, "low", "medium")
        elif kind == "nosql":
            if (re.search(r"\breq\.(body|query)\b(?!\.\w+\s*\))", arg) and not re.search(r"String\(", arg)) or \
                    ("$where" in arg and t):
                return self.add(rule, ln, "Raw request object used as a NoSQL query filter (operator injection).",
                                t or ["remote input: request object"], "high")
            if t and re.search(r":\s*[A-Za-z_$][\w$.]*\s*[,}]", arg) and re.search(r"\b(req\.body|req\.query)\.\w+", "".join(self.env.get(_first_ident(arg), [""]))):
                return self.add(rule, ln, "Request value used in a NoSQL filter without type validation.", t, "medium")
        elif kind == "xss":
            if t and (building or self._var_is_built(arg.strip())):
                return self.add(rule, ln, "User-controlled data written into an HTML response without escaping.", t, "high")
        elif kind == "dom":
            if t:
                return self.add(rule, ln, "Untrusted data written into the DOM as HTML.", t, "high")
        elif kind == "path":
            if t:
                return self.add(rule, ln, "User-controlled file path used in a filesystem operation.", t, "high")
        elif kind == "ssrf":
            if t and self._is_server():
                return self.add(rule, ln, "Server makes a request to a user-controlled URL.", t, "high")
        elif kind == "redirect":
            if t and not re.search(r"\.startsWith\(\s*['\"]/['\"]\s*\)", arg):
                return self.add(rule, ln, "Redirect target is user controlled.", t, "high")
        elif kind == "deser":
            return self.add(rule, ln, "node-serialize unserialize() executes functions embedded in data.", t, "high" if t else "medium",
                            None if t else "high")
        elif kind == "proto":
            if "__proto__" in ",".join(args):
                return None  # keys are filtered
            if any(self.taint_of(a) for a in args[1:]) or (len(args) == 1 and t):
                tt = next((self.taint_of(a) for a in args[1:] if self.taint_of(a)), t)
                return self.add(rule, ln, "Recursive merge of user-controlled object can pollute Object.prototype.", tt, "medium")

    def _var_is_built(self, name: str) -> bool:
        if not re.fullmatch(r"[A-Za-z_$][\w$]*", name):
            return False
        for line in self.lines:
            m = ASSIGN_RE.match(line)
            if m and m.group("lhs") == name and ("${" in m.group("rhs") or "+" in m.group("rhs")):
                return True
        return False

    def _is_server(self) -> bool:
        return bool(re.search(r"require\(['\"](express|koa|fastify|http)['\"]\)|from ['\"](express|koa|fastify)['\"]", self.code))

    def check_patterns(self, line: str, ln: int):
        m = re.search(r"createHash\(\s*['\"](md5|sha1)['\"]", line)
        if m:
            ctx = " ".join(self.lines[max(0, ln - 4):ln + 1])
            if SEC_WORDS.search(ctx):
                self.add("JS-WEAK-HASH", ln, f"{m.group(1).upper()} used in a security context.", None, "high", "high")
            elif self.strict:
                self.add("JS-WEAK-HASH", ln, "Weak hash algorithm.", None, "low", "low")
        if "Math.random()" in line:
            if SEC_WORDS.search(line) or SEC_WORDS.search(self._enclosing_function(ln)):
                self.add("JS-INSECURE-RANDOM", ln, "Math.random() used to generate a security-sensitive value.", None, "high", "medium")
        if re.search(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED['\"]?\]?\s*=\s*['\"]?0", line):
            self.add("JS-TLS-VERIFY", ln, "TLS certificate verification disabled.", None, "high", "medium")
        if re.search(r"\bjwt\.decode\s*\(", line) and SEC_WORDS.search(" ".join(self.lines[ln - 1:ln + 4])):
            self.add("JS-JWT-NOVERIFY", ln, "jwt.decode() does not verify the signature; use jwt.verify().", None, "medium")
        if re.search(r"algorithms\s*:\s*\[[^\]]*['\"]none['\"]", line, re.I):
            self.add("JS-JWT-NOVERIFY", ln, "JWT 'none' algorithm accepted.", None, "high")

    def _enclosing_function(self, ln: int) -> str:
        for i in range(ln - 1, max(-1, ln - 30), -1):
            m = re.search(r"function\s+([\w$]+)|(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s*)?\(", self.lines[i])
            if m:
                return m.group(1) or m.group(2)
        return ""

    def add(self, rule, ln, message, trace, confidence, severity=None):
        if any(f.line == ln and f.category == meta(rule)["category"] for f in self.findings):
            return
        m = meta(rule)
        tr = list(trace or [])
        if tr:
            tr = tr + [f"sink at {self.relpath}:{ln}: {self.raw_lines[ln - 1].strip()[:90]}"]
        f = Finding(rule_id=rule, title=m["title"], severity=severity or m["severity"], confidence=confidence,
                    file=self.relpath, line=ln, message=message, cwe=m["cwe"], owasp=m["owasp"], category=m["category"],
                    language=self.language, snippet=self.raw_lines[ln - 1].strip()[:200],
                    engine="taint" if tr else "rule", function=self._enclosing_function(ln), trace=tr,
                    extra={"route": bool(re.search(r"\b(app|router)\.(get|post|put|delete|patch|all)\(", self.code))})
        self.findings.append(f)


def _first_ident(s: str) -> str:
    m = re.search(r":\s*([A-Za-z_$][\w$]*)", s)
    return m.group(1) if m else ""


def scan_javascript(relpath: str, source: str, language: str = "javascript", strict: bool = False) -> list[Finding]:
    return JSAnalyzer(relpath, source, language, strict).analyze()
