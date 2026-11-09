"""Deterministic remediation templates.

Used (a) when Ollama is unavailable (offline mode) and (b) as a fallback when the
LLM cannot produce a patch that passes validation. Each template rewrites only the
affected region and returns (new_region_text, new_imports, summary) or None.
"""
from __future__ import annotations

import ast
import re
import shlex
from typing import Optional

from .models import Finding

Result = Optional[tuple[str, list, str]]


# ----------------------------------------------------------------------------- helpers
def _indent(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _call_span(text: str, start: int) -> int:
    """Index just after the parenthesis that matches text[start] == '('."""
    depth, q, i = 0, None, start
    while i < len(text):
        c = text[i]
        if q:
            if c == "\\":
                i += 2
                continue
            if c == q:
                q = None
        elif c in "'\"`":
            q = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return -1


def _flatten_concat(node: ast.AST) -> Optional[list]:
    """f-string / '+' concatenation / '%' formatting -> list of str | ast.expr parts."""
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(str(v.value))
            elif isinstance(v, ast.FormattedValue):
                if v.format_spec is not None:
                    return None
                parts.append(v.value)
        return parts
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        l, r = _flatten_concat(node.left), _flatten_concat(node.right)
        if l is None or r is None:
            return None
        return l + r
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod) and isinstance(node.left, ast.Constant) \
            and isinstance(node.left.value, str):
        fmt = node.left.value
        args = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
        pieces = re.split(r"%[sdr]", fmt)
        if len(pieces) - 1 != len(args):
            return None
        out = []
        for i, p in enumerate(pieces):
            out.append(p)
            if i < len(args):
                out.append(args[i])
        return out
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, (ast.Name, ast.Attribute, ast.Subscript, ast.Call)):
        return [node]
    return None


IDENT_CONTEXT = re.compile(r"(ORDER\s+BY|GROUP\s+BY|FROM|INTO|UPDATE|JOIN|TABLE)\s*$", re.I)


def parameterize(parts: list, placeholder: str) -> Optional[tuple[str, list[str]]]:
    """Turn ["SELECT .. '%", <expr q>, "%'"] into ("SELECT .. ?", ['f"%{q}%"'])."""
    sql, params = "", []
    parts = list(parts)
    i = 0
    while i < len(parts):
        p = parts[i]
        if isinstance(p, str):
            sql += p
            i += 1
            continue
        expr = ast.unparse(p)
        nxt = parts[i + 1] if i + 1 < len(parts) and isinstance(parts[i + 1], str) else ""
        if IDENT_CONTEXT.search(sql):
            return None  # identifiers cannot be bound parameters
        pre_wild = sql.endswith("%") and sql[:-1].endswith(("'", '"'))
        if sql.endswith(("'", '"')) or pre_wild:
            quote = sql[-2] if pre_wild else sql[-1]
            sql = sql[:-2] if pre_wild else sql[:-1]
            post_wild = nxt.startswith("%" + quote)
            if not (nxt.startswith(quote) or post_wild):
                return None
            nxt = nxt[2:] if post_wild else nxt[1:]
            if pre_wild or post_wild:
                params.append(f'f"{"%" if pre_wild else ""}{{{expr}}}{"%" if post_wild else ""}"')
            else:
                params.append(expr)
        else:
            params.append(expr)
        sql += placeholder
        if i + 1 < len(parts) and isinstance(parts[i + 1], str):
            parts[i + 1] = nxt
        i += 1
    if not params:
        return None
    return sql, params


def _stmt_at(tree: ast.AST, lineno: int) -> Optional[ast.stmt]:
    best = None
    for n in ast.walk(tree):
        if isinstance(n, ast.stmt) and n.lineno <= lineno <= (n.end_lineno or n.lineno) and \
                not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.If, ast.For, ast.While, ast.With, ast.Try)):
            best = n
    return best


# ----------------------------------------------------------------------------- python
def py_fix(f: Finding, region: str, start: int, file_source: str, project_sources: dict) -> Result:
    lines = region.split("\n")
    rel = f.line - start
    if not (0 <= rel < len(lines)):
        return None
    line = lines[rel]
    imports: list[str] = []
    cat, rid = f.category, f.rule_id

    def done(new_lines, summary):
        return "\n".join(new_lines), imports, summary

    if rid == "PY-DESER-YAML":
        new = re.sub(r"yaml\.(load|unsafe_load|full_load)\(", "yaml.safe_load(", line)
        new = re.sub(r",\s*Loader\s*=\s*[\w.]+", "", new)
        if new != line:
            lines[rel] = new
            return done(lines, "Parse YAML with yaml.safe_load so arbitrary Python objects cannot be constructed.")
    if rid == "PY-TLS-VERIFY" and "verify=False" in line:
        lines[rel] = line.replace("verify=False", "verify=True")
        return done(lines, "Re-enable TLS certificate verification.")
    if rid == "PY-FLASK-DEBUG" and "debug=True" in line:
        lines[rel] = line.replace("debug=True", 'debug=os.environ.get("FLASK_DEBUG") == "1"')
        imports.append("import os")
        return done(lines, "Debug mode is now opt-in via the FLASK_DEBUG environment variable.")
    if rid == "PY-JWT-NOVERIFY":
        new = re.sub(r",\s*options\s*=\s*\{\s*['\"]verify_signature['\"]\s*:\s*False\s*\}", "", line)
        new = re.sub(r",\s*verify\s*=\s*False", "", new)
        if new != line:
            lines[rel] = new
            return done(lines, "Verify JWT signatures (signature verification was disabled).")
    if rid == "PY-INSECURE-RANDOM":
        new = line.replace("random.choice(", "secrets.choice(").replace("random.random()", "secrets.SystemRandom().random()")
        new = re.sub(r"random\.randint\(\s*([^,()]+?)\s*,\s*([^,()]+?)\s*\)",
                     lambda m: f"secrets.randbelow({m.group(2)} - {m.group(1)} + 1) + {m.group(1)}", new)
        if new != line and "random." not in new.replace("secrets.SystemRandom", ""):
            lines[rel] = new
            imports.append("import secrets")
            return done(lines, "Generate security-sensitive values with the cryptographically secure `secrets` module.")
    if rid == "PY-TEMPFILE":
        m = re.search(r"tempfile\.mktemp\(", line)
        if m:
            end = _call_span(line, m.end() - 1)
            args = line[m.end():end - 1]
            lines[rel] = line[:m.start()] + f"tempfile.NamedTemporaryFile(delete=False{', ' + args if args.strip() else ''}).name" + line[end:]
            return done(lines, "Create the temporary file atomically with NamedTemporaryFile instead of race-prone mktemp().")
    if cat == "secrets":
        m = re.match(r"^(\s*)([A-Za-z_][\w]*)\s*=\s*(['\"]).*\3\s*(#.*)?$", line)
        if m:
            lines[rel] = f'{m.group(1)}{m.group(2)} = os.environ["{m.group(2)}"]'
            imports.append("import os")
            return done(lines, f"Load {m.group(2)} from the environment instead of source code (rotate the exposed value).")
    if rid == "PY-CODE-EVAL" and re.search(r"(?<![\w.])eval\(", line):
        lines[rel] = re.sub(r"(?<![\w.])eval\(", "ast.literal_eval(", line, count=1)
        imports.append("import ast")
        return done(lines, "Replace eval() with ast.literal_eval(), which only accepts Python literals.")
    if rid == "PY-DESER-PICKLE" and "pickle.loads(" in line:
        lines[rel] = line.replace("pickle.loads(", "json.loads(")
        imports.append("import json")
        return done(lines, "Deserialize untrusted data as JSON instead of pickle (pickle can execute code).")

    try:
        tree = ast.parse(file_source)
    except SyntaxError:
        return None
    stmt = _stmt_at(tree, f.line)
    if stmt is None:
        return None
    s_rel, e_rel = stmt.lineno - start, (stmt.end_lineno or stmt.lineno) - start
    if s_rel < 0 or e_rel >= len(lines) or s_rel != e_rel:
        return None  # multi-line statements are left to the LLM
    ind = _indent(lines[s_rel])

    if cat == "sqli":
        placeholder = "?" if any("sqlite3" in s for s in project_sources.values()) else "%s"
        call = next((n for n in ast.walk(stmt) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
                     and n.func.attr in ("execute", "executemany") and n.args), None)
        if call is None or len(call.args) != 1:
            return None
        arg = call.args[0]
        assign_line = None
        if isinstance(arg, ast.Name):  # query built in a previous statement
            for n in ast.walk(tree):
                if isinstance(n, ast.Assign) and n.lineno < f.line and any(isinstance(t, ast.Name) and t.id == arg.id for t in n.targets) \
                        and start <= n.lineno and n.lineno == (n.end_lineno or n.lineno):
                    assign_line = n
            if assign_line is None:
                return None
            parts = _flatten_concat(assign_line.value)
        else:
            parts = _flatten_concat(arg)
        if not parts:
            return None
        res = parameterize(parts, placeholder)
        if res is None:
            return None
        sql, params = res
        ptuple = "(" + ", ".join(params) + ("," if len(params) == 1 else "") + ")"
        if assign_line is not None:
            a_rel = assign_line.lineno - start
            seg = ast.get_source_segment(file_source, assign_line.value)
            lines[a_rel] = lines[a_rel].replace(seg, repr(sql).replace("'", '"') if "'" in sql and '"' not in sql else repr(sql), 1)
            seg2 = ast.get_source_segment(file_source, arg)
            line_s = lines[s_rel]
            pos = line_s.find(f"{call.func.attr}({seg2}")
            if pos < 0:
                return None
            lines[s_rel] = line_s[:pos] + f"{call.func.attr}({seg2}, {ptuple}" + line_s[pos + len(call.func.attr) + 1 + len(seg2):]
        else:
            seg = ast.get_source_segment(file_source, arg)
            lit = '"' + sql.replace('"', '\\"') + '"'
            lines[s_rel] = lines[s_rel].replace(seg, f"{lit}, {ptuple}", 1)
        return done(lines, "Use a parameterized query; user input is bound as a parameter instead of concatenated into SQL.")

    if cat == "cmdi":
        call = next((n for n in ast.walk(stmt) if isinstance(n, ast.Call) and ast.unparse(n.func) in
                     ("os.popen", "os.system", "subprocess.check_output", "subprocess.run", "subprocess.call")), None)
        if call is None or not call.args:
            return None
        parts = _flatten_concat(call.args[0])
        if not parts:
            return None
        argv: list[str] = []
        for p in parts:
            if isinstance(p, str):
                toks = shlex.split(p) if p.strip() else []
                argv += [repr(t).replace("'", '"') for t in toks]
            else:
                argv.append(ast.unparse(p))
        if not argv or not argv[0].startswith('"'):
            return None
        arglist = "[" + ", ".join(argv) + "]"
        fn = ast.unparse(call.func)
        seg = ast.get_source_segment(file_source, call)
        text = lines[s_rel]
        if fn == "os.popen" and f"{seg}.read()" in text:
            text = text.replace(f"{seg}.read()", f"subprocess.run({arglist}, capture_output=True, text=True, check=False).stdout")
        elif fn == "os.system":
            text = text.replace(seg, f"subprocess.run({arglist}, check=False).returncode")
        elif fn.startswith("subprocess."):
            kws = [k for k in call.keywords if k.arg != "shell"]
            new = f"{fn}({arglist}" + "".join(f", {ast.unparse(k)}" for k in kws) + ")"
            text = text.replace(seg, new)
        else:
            return None
        lines[s_rel] = text
        imports.append("import subprocess")
        return done(lines, "Run the command as an argument list without a shell so input cannot inject shell syntax.")

    if cat == "path-traversal":
        call = next((n for n in ast.walk(stmt) if isinstance(n, ast.Call) and ast.unparse(n.func) == "os.path.join" and len(n.args) >= 2), None)
        if call is None:
            return None
        last = ast.get_source_segment(file_source, call.args[-1])
        old = lines[s_rel]
        lines[s_rel] = old.replace(f", {last})", f", os.path.basename({last}))", 1)
        if lines[s_rel] == old:
            return None
        imports.append("import os")
        return done(lines, "Strip directory components from the user-supplied file name so it cannot escape the base directory.")

    if cat == "open-redirect" and isinstance(stmt, ast.Return):
        call = stmt.value if isinstance(stmt.value, ast.Call) else None
        if call is None or not call.args:
            return None
        target = ast.get_source_segment(file_source, call.args[0])
        fn = ast.get_source_segment(file_source, call.func)
        lines[s_rel:s_rel + 1] = [f"{ind}target = {target}",
                                  f'{ind}if not target.startswith("/") or target.startswith("//"):',
                                  f'{ind}    target = "/"',
                                  f"{ind}return {fn}(target)"]
        return done(lines, "Only allow relative redirect targets on this site.")

    if cat == "xss" and isinstance(stmt, ast.Return) and isinstance(stmt.value, ast.JoinedStr):
        seg = ast.get_source_segment(file_source, stmt.value)
        new = re.sub(r"\{([^{}!:]+)\}", lambda m: "{escape(" + m.group(1) + ")}", seg)
        lines[s_rel] = lines[s_rel].replace(seg, new, 1)
        imports.append("from markupsafe import escape")
        return done(lines, "HTML-escape user input before placing it in the response.")

    if cat == "ssti":
        call = next((n for n in ast.walk(stmt) if isinstance(n, ast.Call) and ast.unparse(n.func).endswith("render_template_string")), None)
        if call is None or not call.args:
            return None
        parts = _flatten_concat(call.args[0])
        if not parts:
            return None
        tpl, kw = "", []
        for p in parts:
            if isinstance(p, str):
                tpl += p
            elif isinstance(p, ast.Name):
                tpl += "{{ " + p.id + " }}"
                kw.append(f"{p.id}={p.id}")
            else:
                return None
        seg = ast.get_source_segment(file_source, call.args[0])
        lit = '"' + tpl.replace('"', '\\"') + '"'
        lines[s_rel] = lines[s_rel].replace(seg, lit + (", " + ", ".join(kw) if kw else ""), 1)
        return done(lines, "Pass user input to a constant template as a variable (auto-escaped) instead of compiling it.")
    return None


def stmt_text(src: str, stmt: ast.stmt) -> str:
    return ast.get_source_segment(src, stmt) or ""


# ----------------------------------------------------------------------------- javascript
def _js_concat_parts(expr: str) -> Optional[list]:
    """Split a JS string concatenation / template literal into str and code parts."""
    expr = expr.strip()
    if expr.startswith("`") and expr.endswith("`"):
        body, out, i = expr[1:-1], [], 0
        for m in re.finditer(r"\$\{([^}]+)\}", body):
            out.append(body[i:m.start()])
            out.append(("code", m.group(1).strip()))
            i = m.end()
        out.append(body[i:])
        return out
    tokens, depth, cur, q = [], 0, "", None
    for c in expr:
        if q:
            cur += c
            if c == q:
                q = None
            continue
        if c in "'\"":
            q = c
        if c in "([{":
            depth += 1
        if c in ")]}":
            depth -= 1
        if c == "+" and depth == 0:
            tokens.append(cur.strip()); cur = ""
            continue
        cur += c
    tokens.append(cur.strip())
    out = []
    for t in tokens:
        if re.fullmatch(r"'[^']*'|\"[^\"]*\"", t):
            out.append(t[1:-1])
        elif t:
            out.append(("code", t))
        else:
            return None
    return out


def js_fix(f: Finding, region: str, start: int, file_source: str) -> Result:
    lines = region.split("\n")
    rel = f.line - start
    if not (0 <= rel < len(lines)):
        return None
    line = lines[rel]
    imports: list[str] = []
    rid = f.rule_id

    def done(summary):
        return "\n".join(lines), imports, summary

    if rid == "JS-INSECURE-RANDOM" and "Math.random()" in line:
        new = re.sub(r"Math\.random\(\)\.toString\(36\)(\.(slice|substr|substring)\([^)]*\))?", 'crypto.randomBytes(16).toString("hex")', line)
        new = new.replace("Math.random()", "(crypto.randomInt(0, 2 ** 48) / 2 ** 48)")
        lines[rel] = new
        if not re.search(r"require\(['\"]crypto['\"]\)|from ['\"]crypto['\"]", file_source):
            imports.append('const crypto = require("crypto");')
        return done("Generate the token with crypto.randomBytes (CSPRNG) instead of Math.random().")
    if rid == "JS-TLS-VERIFY":
        lines[rel] = re.sub(r"rejectUnauthorized\s*:\s*false", "rejectUnauthorized: true", line)
        return done("Re-enable TLS certificate verification.")
    if f.category == "secrets":
        m = re.match(r"^(\s*)(const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(['\"`]).*\4\s*;?\s*$", line)
        if m:
            lines[rel] = f"{m.group(1)}{m.group(2)} {m.group(3)} = process.env.{m.group(3)};"
            return done(f"Read {m.group(3)} from the environment (rotate the exposed value).")
    if rid == "JS-DOM-XSS" and ".innerHTML" in line:
        lines[rel] = line.replace(".innerHTML", ".textContent")
        return done("Insert untrusted text with textContent so it is never parsed as HTML.")
    if rid == "JS-DESER" and "unserialize(" in line:
        lines[rel] = re.sub(r"(?:serialize\.)?unserialize\(", "JSON.parse(", line)
        return done("Parse the cookie as JSON; node-serialize executes embedded functions.")
    if rid == "JS-OPEN-REDIRECT":
        m = re.search(r"res\.redirect\(", line)
        if m:
            end = _call_span(line, m.end() - 1)
            arg = line[m.end():end - 1].strip()
            ind = _indent(line)
            lines[rel:rel + 1] = [f"{ind}const target = String({arg} || \"/\");",
                                  f'{ind}res.redirect(target.startsWith("/") && !target.startsWith("//") ? target : "/");']
            return done("Only allow relative redirect targets on this site.")
    if rid == "JS-JWT-NOVERIFY" and "jwt.decode(" in line:
        secret = "JWT_SECRET" if re.search(r"\bJWT_SECRET\b", file_source) else "process.env.JWT_SECRET"
        m = re.search(r"jwt\.decode\(", line)
        end = _call_span(line, m.end() - 1)
        arg = line[m.end():end - 1]
        lines[rel] = line[:m.start()] + f'jwt.verify({arg}, {secret}, {{ algorithms: ["HS256"] }})' + line[end:]
        return done("Verify the token signature with jwt.verify() instead of decoding it blindly.")
    if rid == "JS-NOSQLI":
        new = re.sub(r"(?<![\w$(])(req\.(?:body|query)\.[\w$]+)", r"String(\1)", line)
        if new != line:
            lines[rel] = new
            return done("Coerce request values to strings so query operators like {$ne: null} cannot be injected.")
    if rid == "JS-PROTO-POLLUTION":
        new = re.sub(r"(_\.merge\([^,]+,\s*)(req\.body)\)",
                     r'\1JSON.parse(JSON.stringify(\2), (k, v) => (["__proto__", "constructor", "prototype"].includes(k) ? undefined : v)))', line)
        if new != line:
            lines[rel] = new
            return done("Strip __proto__/constructor/prototype keys before merging user input.")
    if rid == "JS-PATH-TRAVERSAL":
        m = re.search(r"path\.join\(", line)
        if m:
            end = _call_span(line, m.end() - 1)
            args = [a.strip() for a in line[m.end():end - 1].split(",")]
            if len(args) >= 2 and not args[-1].startswith(("'", '"')):
                args[-1] = f"path.basename({args[-1]})"
                lines[rel] = line[:m.end()] + ", ".join(args) + line[end - 1:]
                return done("Strip directory components from the user-supplied file name.")
    if rid in ("JS-SQLI", "JS-CMDI", "JS-XSS"):
        head = re.search(r"\.(query|raw|execute)\(|(?<![\w$])(exec|execSync)\(|res\.(send|write|end)\(", line)
        if not head:
            return None
        end = _call_span(line, head.end() - 1)
        from .analyzers.javascript import split_top_args
        args = split_top_args(line[head.end():end - 1])
        if not args:
            return None
        parts = _js_concat_parts(args[0])
        if not parts:
            return None
        if rid == "JS-XSS":
            new0 = "`" + "".join(p if isinstance(p, str) else "${escapeHtml(" + p[1] + ")}" for p in parts) + "`"
            lines[rel] = line[:head.end()] + ", ".join([new0] + args[1:]) + line[end - 1:]
            if "escapeHtml" not in file_source:
                imports.append("const escapeHtml = (s) => String(s).replace(/[&<>\"']/g, (c) => ({ \"&\": \"&amp;\", \"<\": \"&lt;\", \">\": \"&gt;\", '\"': \"&quot;\", \"'\": \"&#39;\" })[c]);")
            return done("HTML-escape user input before writing it into the response.")
        if rid == "JS-SQLI":
            sql, params, i = "", [], 0
            while i < len(parts):
                p = parts[i]
                if isinstance(p, str):
                    sql += p
                else:
                    if sql.endswith(("'", '"')):
                        sql = sql[:-1]
                        if i + 1 < len(parts) and isinstance(parts[i + 1], str) and parts[i + 1][:1] in "'\"":
                            parts[i + 1] = parts[i + 1][1:]
                    sql += "?"
                    params.append(p[1])
                i += 1
            if not params:
                return None
            lines[rel] = line[:head.end()] + ", ".join([f'"{sql}"', "[" + ", ".join(params) + "]"] + args[1:]) + line[end - 1:]
            return done("Use a parameterized query with ? placeholders.")
        if rid == "JS-CMDI":
            argv: list[str] = []
            for p in parts:
                if isinstance(p, str):
                    argv += [f'"{t}"' for t in p.split()]
                else:
                    argv.append(p[1])
            if not argv or not argv[0].startswith('"'):
                return None
            fn = "execFile" if head.group(2) == "exec" or "exec(" in head.group(0) else "execFileSync"
            lines[rel] = line[:head.start()] + f"{fn}({argv[0]}, [{', '.join(argv[1:])}]" + \
                ("".join(", " + a for a in args[1:])) + line[end - 1:]
            if not re.search(rf"\b{fn}\b", file_source.split(line)[0]):
                imports.append(f'const {{ {fn} }} = require("child_process");')
            return done("Run the program with execFile and an argument array (no shell).")
    return None


def template_fix(f: Finding, region: str, start: int, file_source: str, project_sources: dict) -> Result:
    try:
        if f.language == "python":
            return py_fix(f, region, start, file_source, project_sources)
        if f.language in ("javascript", "typescript"):
            return js_fix(f, region, start, file_source)
    except Exception:  # templates are best effort; never crash the pipeline
        return None
    return None
