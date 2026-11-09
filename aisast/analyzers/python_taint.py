"""Python analyzer: AST-based, flow-sensitive taint tracking with inter-procedural
(project-wide) function summaries, plus AST pattern rules.

Design notes
------------
* Every variable carries a *taint* (origins of attacker-controlled data, each with a
  human-readable trace), a *safe* flag (proven built only from constants/sanitizers)
  and, when known, a *constant value*. Variables that are none of these are "unknown".
* Sanitizers are category-aware: html.escape() neutralises XSS but not SQL injection;
  int()/uuid.UUID() neutralise everything.
* Branches whose condition folds to a constant are analysed precisely (only the taken
  branch); otherwise both branches are merged (weak updates).
* Containers are field-sensitive for constant keys (dict["k"], ConfigParser.set/get) and
  container mutation (append/extend/add/update/...) taints the receiver.
* Validation guards (`if '../' in p: return`, `if x not in ALLOWED: abort(400)`,
  `if not url.startswith('/'): url = '/'`) clear taint on the guarded variable.
* Sinks fed by tainted data produce high-confidence findings. Dangerous string-built
  sinks fed by *unknown* data produce low-confidence findings (left to AI triage).
* Function summaries record which parameters reach which sinks / the return value
  (with the sanitisation applied on the way), so `find_user(request.args["q"])` in
  app.py is traced into the SQL sink in db.py.
"""
from __future__ import annotations

import ast
import operator
import re
from dataclasses import dataclass, field
from typing import Optional

from ..models import Finding
from ..rules import meta

SOURCE_RE = re.compile(
    r"(?:^|\.)request\.(args|form|values|json|data|cookies|headers|files|GET|POST|body|query_string|"
    r"query_params|path_params|FILES|COOKIES|META|get_json|get_data|stream|full_path|url|environ)\b")
ALL = frozenset({"*"})
# universal sanitizers: the result carries no attacker-controlled characters
UNIVERSAL_SANITIZERS = {
    "int", "float", "bool", "len", "abs", "round", "hash", "ord", "id", "uuid.UUID", "ipaddress.ip_address",
    "url_for", "flask.url_for", "hashlib.sha256", "hashlib.sha512", "hashlib.blake2b", "secrets.compare_digest",
    "hmac.compare_digest", "datetime.date.fromisoformat", "isinstance", "callable",
}
CATEGORY_SANITIZERS = {
    "html.escape": {"xss", "ssti"}, "markupsafe.escape": {"xss", "ssti"}, "escape": {"xss", "ssti"},
    "flask.escape": {"xss", "ssti"}, "bleach.clean": {"xss"}, "cgi.escape": {"xss"}, "markupsafe.Markup.escape": {"xss"},
    "shlex.quote": {"cmdi"}, "pipes.quote": {"cmdi"},
    "os.path.basename": {"path-traversal"}, "werkzeug.utils.secure_filename": {"path-traversal"},
    "secure_filename": {"path-traversal"},
    "urllib.parse.quote": {"xss", "path-traversal", "open-redirect", "cmdi", "ldapi", "xpathi", "sqli"},
    "urllib.parse.quote_plus": {"xss", "path-traversal", "open-redirect", "cmdi", "ldapi", "xpathi", "sqli"},
    "quote": {"xss", "path-traversal", "open-redirect"}, "quote_plus": {"xss", "path-traversal", "open-redirect"},
    "re.escape": {"code-injection"}, "json.dumps": {"code-injection"},
    "ldap3.utils.conv.escape_filter_chars": {"ldapi"}, "escape_filter_chars": {"ldapi"},
    "ldap.filter.escape_filter_chars": {"ldapi"}, "ldap3.utils.dn.escape_rdn": {"ldapi"},
}
SQL_METHODS = {"execute", "executemany", "executescript", "mogrify", "raw"}
SQL_FUNCS = {"sqlalchemy.text", "text"}
CMD_FUNCS = {"os.system", "os.popen", "commands.getoutput", "subprocess.getoutput", "subprocess.getstatusoutput",
             "os.execl", "os.execvp", "os.execv", "os.execlp", "os.spawnl", "os.spawnlp", "os.spawnv", "pty.spawn"}
SUBPROCESS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "subprocess.check_call"}
EVAL_FUNCS = {"eval", "exec", "compile"}
PICKLE_FUNCS = {"pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load", "dill.loads", "marshal.loads",
                "jsonpickle.decode", "shelve.open", "_pickle.loads", "pickle.Unpickler"}
YAML_FUNCS = {"yaml.load", "yaml.load_all", "yaml.unsafe_load", "yaml.full_load", "yaml.unsafe_load_all"}
PATH_FUNCS = {"open", "io.open", "codecs.open", "flask.send_file", "send_file", "os.remove", "os.unlink",
              "shutil.copy", "shutil.copyfile", "shutil.rmtree", "shutil.move", "os.rmdir", "os.listdir",
              "os.path.exists", "os.path.isfile", "os.path.isdir", "os.path.getsize", "os.stat", "os.access",
              "os.makedirs", "os.mkdir", "os.rename", "os.replace", "os.scandir", "glob.glob", "fileinput.input"}
PATH_METHODS = {"read_text", "read_bytes", "write_text", "write_bytes", "unlink", "exists", "is_file", "is_dir",
                "stat", "touch", "mkdir", "iterdir", "rmdir"}
SSRF_FUNCS = {"requests.get", "requests.post", "requests.put", "requests.delete", "requests.head", "requests.patch",
              "requests.request", "urllib.request.urlopen", "urlopen", "urllib.request.Request", "httpx.get",
              "httpx.post", "httpx.request", "urllib3.request"}
REDIRECT_FUNCS = {"redirect", "flask.redirect", "django.shortcuts.redirect", "HttpResponseRedirect"}
SSTI_FUNCS = {"render_template_string", "flask.render_template_string", "jinja2.Template", "Template",
              "mako.template.Template"}
XML_PARSE_FUNCS = {"lxml.etree.fromstring", "lxml.etree.parse", "lxml.etree.XML", "etree.fromstring", "etree.parse",
                   "etree.XML", "xml.dom.minidom.parseString", "xml.dom.minidom.parse", "minidom.parseString",
                   "minidom.parse", "xml.sax.parseString", "xml.sax.parse", "xml.dom.pulldom.parseString",
                   "xml.dom.pulldom.parse"}
RESPONSE_FUNCS = {"make_response", "flask.make_response", "Response", "flask.Response", "HttpResponse", "Markup",
                  "markupsafe.Markup"}
CONTAINER_MUTATORS = {"append", "extend", "insert", "add", "update", "appendleft", "extendleft", "put", "setdefault", "push"}
ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch", "api_route", "websocket"}
SECURITY_WORDS = re.compile(r"pass(word|wd)?|pwd|secret|token|otp|nonce|salt|session|reset|auth|api_?key|sign|credential|key|remember|cookie", re.I)
SECRET_NAME_RE = re.compile(r"(pass(word|wd)?|pwd|secret|api_?key|access_?key|auth_?token|(secret|private|signing|encryption|master)_?key|token|client_?secret)$", re.I)
PLACEHOLDER_RE = re.compile(r"^(|x+|\*+|changeme_?|example|your[-_ ].*|<.*>|\$\{.*\}|\{\{.*\}\}|todo|none|null|test|dummy|placeholder|password|secret)$", re.I)

Taint = dict  # (kind, label, sanitized_categories) -> trace tuple
UNKNOWN = object()


@dataclass
class VarState:
    taint: Taint = field(default_factory=dict)
    safe: bool = False
    const: object = UNKNOWN


@dataclass
class SinkHit:
    category: str
    rule_id: str
    file: str
    line: int
    snippet: str
    function: str
    message: str
    trace: tuple
    severity: Optional[str] = None
    route: bool = False


@dataclass
class FuncInfo:
    name: str
    qualname: str
    module: str          # relative file path
    node: ast.AST
    params: list
    is_method: bool
    is_route: bool
    returns: dict = field(default_factory=dict)          # param idx -> categories sanitized on the way to `return`
    sinks: list = field(default_factory=list)            # (param_idx, SinkHit)


def dotted(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    if isinstance(node, ast.Subscript):
        return dotted(node.value)
    return ""


def merge(*taints: Taint) -> Taint:
    out: Taint = {}
    for t in taints:
        for k, v in t.items():
            if k not in out or len(v) < len(out[k]):
                out[k] = v
    return out


def for_cat(t: Taint, cat: Optional[str]) -> Taint:
    if cat is None:
        return t
    return {k: v for k, v in t.items() if cat not in k[2] and "*" not in k[2]}


def sanitize(t: Taint, cats) -> Taint:
    if cats == ALL:
        return {}
    out: Taint = {}
    for k, v in t.items():
        nk = (k[0], k[1], frozenset(k[2] | set(cats)))
        out[nk] = v
    return out


def has_source(t: Taint, cat: Optional[str] = None) -> bool:
    return any(k[0] == "src" for k in for_cat(t, cat))


def extend(t: Taint, step: str) -> Taint:
    return {k: (v + (step,))[-10:] for k, v in t.items()}


_BINOPS = {ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.FloorDiv: operator.floordiv,
           ast.Mod: operator.mod, ast.Div: operator.truediv, ast.Pow: operator.pow}
_CMPOPS = {ast.Eq: operator.eq, ast.NotEq: operator.ne, ast.Lt: operator.lt, ast.LtE: operator.le, ast.Gt: operator.gt,
           ast.GtE: operator.ge, ast.In: lambda a, b: a in b, ast.NotIn: lambda a, b: a not in b,
           ast.Is: operator.is_, ast.IsNot: operator.is_not}


class ModuleContext:
    def __init__(self, relpath: str, source: str, tree: ast.Module):
        self.relpath = relpath
        self.lines = source.splitlines()
        self.tree = tree
        self.aliases: dict[str, str] = {}        # local name -> fully qualified
        self.imported_from: dict[str, str] = {}  # local name -> module it came from
        self.constants: set[str] = set()
        self.const_values: dict[str, object] = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for a in node.names:
                    self.aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(node, ast.ImportFrom):
                for a in node.names:
                    local = a.asname or a.name
                    if node.module is None:          # from . import db  -> module "db"
                        self.aliases[local] = a.name
                    else:
                        self.aliases[local] = f"{node.module}.{a.name}"
                        self.imported_from[local] = node.module
            elif isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                if value is not None and _is_literal(value):
                    for t in targets:
                        if isinstance(t, ast.Name):
                            self.constants.add(t.id)
                            try:
                                self.const_values[t.id] = ast.literal_eval(value)
                            except (ValueError, SyntaxError, TypeError):
                                pass
        for node in ast.walk(tree):  # function-local imports too
            if isinstance(node, ast.ImportFrom) and node.module and node not in tree.body:
                for a in node.names:
                    self.aliases.setdefault(a.asname or a.name, f"{node.module}.{a.name}")
            elif isinstance(node, ast.Import) and node not in tree.body:
                for a in node.names:
                    self.aliases.setdefault(a.asname or a.name.split(".")[0], a.name if a.asname else a.name.split(".")[0])

    def qual(self, node: ast.AST) -> str:
        name = dotted(node)
        if not name:
            return ""
        head, _, rest = name.partition(".")
        if head in self.aliases:
            full = self.aliases[head]
            return f"{full}.{rest}" if rest else full
        return name

    def line(self, n: int) -> str:
        return self.lines[n - 1].strip() if 0 < n <= len(self.lines) else ""


def _is_literal(node: ast.AST) -> bool:
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_is_literal(e) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(k is None or _is_literal(k) for k in node.keys) and all(_is_literal(v) for v in node.values)
    if isinstance(node, ast.BinOp):
        return _is_literal(node.left) and _is_literal(node.right)
    return False


def _kw(call: ast.Call, name: str) -> Optional[ast.AST]:
    for k in call.keywords:
        if k.arg == name:
            return k.value
    return None


def _truthy_const(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Constant) and bool(node.value)


def _false_const(node: Optional[ast.AST]) -> bool:
    return isinstance(node, ast.Constant) and node.value is False


def _is_string_building(node: ast.AST) -> bool:
    if isinstance(node, ast.JoinedStr):
        return any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"format", "join", "replace"}:
        return True
    return False


def _contains_html(node: ast.AST) -> bool:
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str) and re.search(r"<[a-zA-Z/!]", n.value):
            return True
    return False


def _const_key(node: ast.AST):
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, int)):
        return node.value
    return UNKNOWN


def _ends_with_exit(body: list) -> bool:
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Raise, ast.Return, ast.Continue, ast.Break)):
        return True
    return isinstance(last, ast.Expr) and isinstance(last.value, ast.Call) and \
        dotted(last.value.func).split(".")[-1] in {"abort", "exit", "_exit", "fail"}


class FunctionAnalyzer:
    """Analyzes one function body (or module top level) in a given mode."""

    VALIDATING_CALLS = {"startswith", "endswith", "match", "fullmatch", "search", "isdigit", "isalnum", "isidentifier",
                        "isdecimal", "isnumeric", "isalpha", "urlparse", "urlsplit", "is_safe_url",
                        "url_has_allowed_host_and_scheme", "isascii"}

    def __init__(self, engine: "PythonTaintEngine", ctx: ModuleContext, func: Optional[FuncInfo], mode: str):
        self.engine, self.ctx, self.func, self.mode = engine, ctx, func, mode  # mode: summary | main
        self.env: dict[str, VarState] = {}
        self.depth = 0
        self.return_taint: list[Taint] = []
        self.fname = func.qualname if func else "<module>"
        self.xxe_parsers: set[str] = set()
        self.lists: dict[str, Optional[list]] = {}     # precise element model for list literals
        self.derived: dict[str, str] = {}               # url = urlparse(x) -> url derived from x
        self.dead = False                                # current path already returned/raised
        self.loop_exits: list[list] = []                 # snapshots taken at break/continue

    # ---------- path-sensitive joins ----------
    def snapshot(self):
        return (dict(self.env), {k: (list(v) if v is not None else None) for k, v in self.lists.items()}, self.dead)

    def restore(self, snap):
        self.env, self.lists, self.dead = dict(snap[0]), {k: (list(v) if v is not None else None) for k, v in snap[1].items()}, snap[2]

    @staticmethod
    def _join_state(a: Optional[VarState], b: Optional[VarState]) -> VarState:
        if a is None or b is None:
            x = a or b
            return VarState(dict(x.taint), False, UNKNOWN)
        same_const = a.const is not UNKNOWN and b.const is not UNKNOWN and type(a.const) is type(b.const) and a.const == b.const
        return VarState(merge(a.taint, b.taint), a.safe and b.safe, a.const if same_const else UNKNOWN)

    def join(self, *snaps):
        live = [sn for sn in snaps if not sn[2]] or list(snaps[-1:])
        if len(live) == 1:
            self.restore(live[0])
            return
        env, lists = {}, {}
        keys = set().union(*[set(sn[0]) for sn in live])
        for k in keys:
            st = live[0][0].get(k)
            for sn in live[1:]:
                st = self._join_state(st, sn[0].get(k)) if st is not None or sn[0].get(k) is not None else None
            if st is not None:
                env[k] = st
        for k in set().union(*[set(sn[1]) for sn in live]):
            vals = [sn[1].get(k) for sn in live]
            if any(v is None for v in vals) or len({len(v) for v in vals}) != 1:
                lists[k] = None
            else:
                lists[k] = [self._join_state(*col) if len(col) == 2 else
                            __import__("functools").reduce(self._join_state, col) for col in zip(*vals)]
        self.env, self.lists, self.dead = env, lists, all(sn[2] for sn in snaps)

    # ---------- environment ----------
    def seed(self):
        if not self.func:
            return
        for i, p in enumerate(self.func.params):
            if self.mode == "summary":
                self.env[p] = VarState({("param", i, frozenset()): (f"parameter '{p}' of {self.func.qualname}()",)})
            elif self.func.is_route and p not in ("self", "cls"):
                lbl = f"{self.ctx.relpath}:{self.func.node.lineno}"
                self.env[p] = VarState({("src", f"url:{p}@{lbl}", frozenset()): (
                    f"remote input: URL path parameter '{p}' of route {self.func.qualname}() ({lbl})",)})

    def _store(self, key: str, st: VarState):
        self.env[key] = st

    def assign(self, target: ast.AST, state: VarState, line: int):
        if isinstance(target, (ast.Tuple, ast.List)):
            for e in target.elts:
                self.assign(e, VarState(state.taint, state.safe), line)
            return
        if isinstance(target, ast.Starred):
            return self.assign(target.value, state, line)
        here = f"{self.ctx.relpath}:{line}"
        t = {k: (v if (v and here in v[-1]) else (v + (f"{here}: {self.ctx.line(line)[:90]}",))[-10:]) for k, v in state.taint.items()}
        if isinstance(target, ast.Subscript):
            base = dotted(target.value)
            if not base:
                return
            kt = self.taint_of(target.slice)
            if self.mode == "main" and base.split(".")[-1].lower().endswith("session") and has_source(merge(t, kt), "trust-boundary"):
                t2 = merge(t, kt)
                self.hit("trust-boundary", "PY-TRUST-BOUNDARY", target, "Untrusted request data stored in the server-side session.", t2)
            key = _const_key(target.slice)
            if key is not UNKNOWN:
                self.engine.keyed.add((id(self), base))
                self._store(f"{base}[{key!r}]", VarState(t, state.safe))
            else:  # d[x] = tainted -> taints the whole container (weak update)
                old = self.env.get(base, VarState())
                self.env[base] = VarState(merge(old.taint, t), old.safe and state.safe)
            return
        key = dotted(target) if isinstance(target, (ast.Name, ast.Attribute)) else None
        if not key:
            return
        for k in [k for k in self.env if k.startswith(key + "[")]:
            del self.env[k]   # re-assigning a container resets its keyed entries
        self.lists.pop(key, None)
        self._store(key, VarState(t, state.safe, state.const))

    def list_elem(self, node: ast.Subscript) -> Optional[VarState]:
        if not isinstance(node.value, ast.Name) or self.lists.get(node.value.id) is None:
            return None
        i = self.const_of(node.slice)
        lst = self.lists[node.value.id]
        if isinstance(i, int) and -len(lst) <= i < len(lst):
            return lst[i]
        return None

    def container_taint(self, base: str) -> Taint:
        parts = [self.env[base].taint] if base in self.env else []
        parts += [v.taint for k, v in self.env.items() if k.startswith(base + "[")]
        return merge(*parts)

    # ---------- constant folding ----------
    def const_of(self, node: Optional[ast.AST]):
        try:
            if node is None:
                return UNKNOWN
            if isinstance(node, ast.Constant):
                return node.value
            if isinstance(node, ast.Name):
                if node.id in self.env:
                    return self.env[node.id].const
                return self.ctx.const_values.get(node.id, UNKNOWN)
            if isinstance(node, ast.BinOp) and type(node.op) in _BINOPS:
                a, b = self.const_of(node.left), self.const_of(node.right)
                if a is UNKNOWN or b is UNKNOWN:
                    return UNKNOWN
                if isinstance(node.op, ast.Pow) and isinstance(b, int) and b > 64:
                    return UNKNOWN
                if isinstance(node.op, ast.Mult) and (isinstance(a, str) or isinstance(b, str)) and max(len(str(a)), len(str(b))) * 2 > 10000:
                    return UNKNOWN
                return _BINOPS[type(node.op)](a, b)
            if isinstance(node, ast.UnaryOp):
                v = self.const_of(node.operand)
                if v is UNKNOWN:
                    return UNKNOWN
                return {ast.Not: lambda x: not x, ast.USub: lambda x: -x, ast.UAdd: lambda x: +x}.get(type(node.op), lambda x: UNKNOWN)(v)
            if isinstance(node, ast.BoolOp):
                vals = [self.const_of(v) for v in node.values]
                if isinstance(node.op, ast.And):
                    for v in vals:
                        if v is UNKNOWN:
                            return UNKNOWN
                        if not v:
                            return v
                    return vals[-1]
                for v in vals:
                    if v is UNKNOWN:
                        return UNKNOWN
                    if v:
                        return v
                return vals[-1]
            if isinstance(node, ast.Compare) and len(node.ops) == 1 and type(node.ops[0]) in _CMPOPS:
                a, b = self.const_of(node.left), self.const_of(node.comparators[0])
                if a is UNKNOWN or b is UNKNOWN:
                    return UNKNOWN
                return _CMPOPS[type(node.ops[0])](a, b)
            if isinstance(node, ast.Subscript):
                if isinstance(node.value, ast.Name):
                    el = self.list_elem(node)
                    if el is not None:
                        return el.const
                    key = _const_key(node.slice)
                    if key is not UNKNOWN and f"{node.value.id}[{key!r}]" in self.env:
                        return self.env[f"{node.value.id}[{key!r}]"].const
                v = self.const_of(node.value)
                if v is UNKNOWN or not isinstance(v, (str, tuple, list)):
                    return UNKNOWN
                if isinstance(node.slice, ast.Slice):
                    lo, hi = self.const_of(node.slice.lower) if node.slice.lower else None, self.const_of(node.slice.upper) if node.slice.upper else None
                    if lo is UNKNOWN or hi is UNKNOWN or node.slice.step is not None:
                        return UNKNOWN
                    return v[lo:hi]
                i = self.const_of(node.slice)
                return v[i] if isinstance(i, int) else UNKNOWN
            if isinstance(node, ast.IfExp):
                c = self.const_of(node.test)
                return UNKNOWN if c is UNKNOWN else self.const_of(node.body if c else node.orelse)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and not node.keywords:
                recv = self.const_of(node.func.value)
                args = [self.const_of(a) for a in node.args]
                if isinstance(recv, str) and all(a is not UNKNOWN for a in args) and node.func.attr in {
                        "upper", "lower", "strip", "startswith", "endswith", "replace", "find", "count", "split", "isdigit"}:
                    return getattr(recv, node.func.attr)(*args)
        except Exception:  # noqa: BLE001 - folding is best effort
            return UNKNOWN
        return UNKNOWN

    # ---------- expression evaluation ----------
    def source_of(self, node: ast.AST) -> Optional[str]:
        q = self.ctx.qual(node)
        m = SOURCE_RE.search(q) or SOURCE_RE.search(dotted(node))
        if m:
            return f"request.{m.group(1)}"
        if isinstance(node, ast.Call) and q in {"input", "raw_input"}:
            return "input()"
        if q == "sys.argv":
            return "sys.argv"
        return None

    def taint_of(self, node: Optional[ast.AST]) -> Taint:
        if node is None:
            return {}
        src = self.source_of(node) if isinstance(node, (ast.Attribute, ast.Call, ast.Subscript)) else None
        if src:
            ln = getattr(node, "lineno", 0)
            kind = "remote input" if src.startswith("request") else "local input"
            return {("src", f"{src}@{self.ctx.relpath}:{ln}", frozenset()): (
                f"{kind}: {src} at {self.ctx.relpath}:{ln} — {self.ctx.line(ln)[:90]}",)}
        if isinstance(node, ast.Name):
            if any(k.startswith(node.id + "[") for k in self.env):
                return self.container_taint(node.id)
            return dict(self.env.get(node.id, VarState()).taint)
        if isinstance(node, ast.Attribute):
            key = dotted(node)
            if key in self.env:
                return dict(self.env[key].taint)
            return self.taint_of(node.value)
        if isinstance(node, ast.Subscript):
            base = dotted(node.value)
            key = _const_key(node.slice)
            el = self.list_elem(node)
            if el is not None:
                return dict(el.taint)
            if base and key is not UNKNOWN and f"{base}[{key!r}]" in self.env:
                return dict(self.env[f"{base}[{key!r}]"].taint)
            if base and key is not UNKNOWN and any(k.startswith(base + "[") for k in self.env):
                return dict(self.env.get(base, VarState()).taint)   # other constant keys hold untainted data
            return self.taint_of(node.value)
        if isinstance(node, ast.Call):
            return self.call_taint(node)
        if isinstance(node, (ast.Compare, ast.Lambda, ast.Constant)):
            return {}
        if isinstance(node, ast.IfExp):
            c = self.const_of(node.test)
            if c is not UNKNOWN:
                return self.taint_of(node.body if c else node.orelse)
            if self._allowlist_ifexp(node):
                return {}
        if isinstance(node, ast.Dict):
            return merge(*[self.taint_of(v) for v in node.values])
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            elt = node.elt if not isinstance(node, ast.DictComp) else node.value
            gen_t = merge(*[self.taint_of(g.iter) for g in node.generators])
            # comprehension variable bound to the iterable's taint
            saved = {}
            for g in node.generators:
                for n in ast.walk(g.target):
                    if isinstance(n, ast.Name):
                        saved[n.id] = self.env.get(n.id)
                        self.env[n.id] = VarState(gen_t)
            t = self.taint_of(elt)
            for k, v in saved.items():
                if v is None:
                    self.env.pop(k, None)
                else:
                    self.env[k] = v
            return t
        out: Taint = {}
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                out = merge(out, self.taint_of(child))
        return out

    def _allowlist_ifexp(self, node: ast.IfExp) -> bool:
        return isinstance(node.test, ast.Compare) and len(node.test.ops) == 1 and isinstance(node.test.ops[0], ast.In) \
            and ast.dump(node.test.left) == ast.dump(node.body) and self.is_safe(node.orelse) \
            and self.is_safe(node.test.comparators[0])

    def sanitizer_cats(self, q: str):
        short = q.split(".")[-1]
        if q in UNIVERSAL_SANITIZERS:
            return ALL
        if q in CATEGORY_SANITIZERS:
            return CATEGORY_SANITIZERS[q]
        if short in {"secure_filename", "basename"}:
            return {"path-traversal"}
        if short in {"escape", "escape_html", "html_escape"} or short.startswith("escape_for_html"):
            return {"xss", "ssti"}
        if short in {"escape_filter_chars", "escape_rdn"}:
            return {"ldapi"}
        return None

    def call_taint(self, node: ast.Call) -> Taint:
        q = self.ctx.qual(node.func)
        cats = self.sanitizer_cats(q)
        args_t = merge(*([self.taint_of(a) for a in node.args] + [self.taint_of(k.value) for k in node.keywords]))
        if cats is not None:
            return sanitize(args_t, cats)
        callee = self.engine.resolve(self.ctx, node, self.func)
        if callee is not None:
            args = self.bind_args(node, callee)
            out: Taint = {}
            for idx, scats in callee.returns.items():
                if idx in args:
                    out = merge(out, sanitize(extend(self.taint_of(args[idx]), f"returned from {callee.qualname}()"), scats))
            return out
        if isinstance(node.func, ast.Attribute):
            base = dotted(node.func.value)
            attr = node.func.attr
            # keyed reads: d.get("k"), conf.get("section", "k")
            if attr in ("get", "getint", "getboolean", "pop") and base and node.args:
                keys = [_const_key(a) for a in node.args[:2]]
                if len(keys) == 2 and UNKNOWN not in keys and f"{base}[{keys[0]!r},{keys[1]!r}]" in self.env:
                    return dict(self.env[f"{base}[{keys[0]!r},{keys[1]!r}]"].taint)
                if keys[0] is not UNKNOWN and f"{base}[{keys[0]!r}]" in self.env:
                    return merge(self.env[f"{base}[{keys[0]!r}]"].taint, self.taint_of(node.args[1]) if len(node.args) > 1 and attr == "get" and not any(k.startswith(f"{base}[{keys[0]!r},") for k in self.env) else {})
                if keys[0] is not UNKNOWN and any(k.startswith(base + "[") for k in self.env):
                    return dict(self.env.get(base, VarState()).taint)
            return merge(args_t, self.taint_of(node.func.value))
        return args_t

    def is_safe(self, node: Optional[ast.AST]) -> bool:
        """True when the value is provably built from constants / universal sanitizers only."""
        if node is None or isinstance(node, ast.Constant):
            return True
        if self.const_of(node) is not UNKNOWN:
            return True
        if isinstance(node, ast.Name):
            if node.id in self.env:
                return self.env[node.id].safe and not self.env[node.id].taint
            return node.id in self.ctx.constants or node.id.isupper()
        if isinstance(node, ast.Call):
            q = self.ctx.qual(node.func)
            cats = self.sanitizer_cats(q)
            if cats == ALL or q.split(".")[-1] in {"secure_filename", "escape", "basename", "len", "url_for"}:
                return True
            if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Constant):
                return all(self.is_safe(a) for a in node.args)
            return False
        if isinstance(node, ast.JoinedStr):
            return all(self.is_safe(v.value) if isinstance(v, ast.FormattedValue) else True for v in node.values)
        if isinstance(node, ast.IfExp) and self._allowlist_ifexp(node):
            return True
        if isinstance(node, (ast.BinOp, ast.Tuple, ast.List, ast.BoolOp, ast.IfExp)):
            return all(self.is_safe(c) for c in ast.iter_child_nodes(node) if isinstance(c, ast.expr))
        if isinstance(node, ast.Compare):
            return True
        if isinstance(node, ast.Subscript):
            el = self.list_elem(node)
            if el is not None:
                return el.safe and not el.taint
            base, key = dotted(node.value), _const_key(node.slice)
            if base and key is not UNKNOWN and f"{base}[{key!r}]" in self.env:
                st = self.env[f"{base}[{key!r}]"]
                return st.safe and not st.taint
            return False
        if isinstance(node, ast.Attribute):
            if node.attr.isupper() and isinstance(node.value, (ast.Name, ast.Attribute)) and dotted(node.value) not in self.env:
                return True   # module.CONSTANT
            return dotted(node) in self.env and self.env[dotted(node)].safe
        return False

    def has_unknown_input(self, node: ast.AST) -> bool:
        """True if the expression reads a value of unknown provenance (parameter, global,
        attribute of an object) rather than only constants / proven-safe locals."""
        import builtins
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
                if n.id in self.env:
                    st = self.env[n.id]
                    if not (st.safe or st.const is not UNKNOWN) or st.taint:
                        return True
                elif n.id in self.ctx.aliases or n.id in self.ctx.constants or hasattr(builtins, n.id) or n.id.isupper() \
                        or n.id in self.engine.functions:
                    continue
                else:
                    return True
            elif isinstance(n, ast.Subscript) and isinstance(n.value, ast.Name) and not self.is_safe(n):
                if n.value.id in self.env and self.env[n.value.id].taint:
                    return True
        return False

    def state_of(self, node: ast.AST) -> VarState:
        t = self.taint_of(node)
        c = self.const_of(node)
        return VarState(t, (not t) and self.is_safe(node), c if not t else UNKNOWN)

    def bind_args(self, call: ast.Call, callee: FuncInfo) -> dict:
        offset = 1 if (callee.is_method and isinstance(call.func, ast.Attribute)) else 0
        bound = {}
        for i, a in enumerate(call.args):
            if not isinstance(a, ast.Starred):
                bound[i + offset] = a
        for k in call.keywords:
            if k.arg in callee.params:
                bound[callee.params.index(k.arg)] = k.value
        return bound

    # ---------- statements ----------
    def run(self, body: list):
        self.seed()
        self.block(body)
        if self.mode == "summary" and self.func:
            per_idx: dict[int, list] = {}
            for t in self.return_taint:
                for k in t:
                    if k[0] == "param":
                        per_idx.setdefault(k[1], []).append(k[2])
            self.func.returns = {i: frozenset.intersection(*map(frozenset, cs)) for i, cs in per_idx.items()}

    def block(self, stmts: list):
        for s in stmts:
            if self.dead:
                return
            self.stmt(s)

    @staticmethod
    def _case_matches(p, subj):
        """True/False when a match-case pattern statically matches a constant subject, else None."""
        if isinstance(p, ast.MatchValue) and isinstance(p.value, ast.Constant):
            return p.value.value == subj
        if isinstance(p, ast.MatchSingleton):
            return p.value is subj
        if isinstance(p, ast.MatchOr):
            rs = [FunctionAnalyzer._case_matches(x, subj) for x in p.patterns]
            return True if True in rs else None if None in rs else False
        if isinstance(p, ast.MatchAs) and p.pattern is None:
            return True
        return None

    def branch(self, test: ast.AST, body: list, orelse: list):
        c = self.const_of(test)
        if c is not UNKNOWN:
            self.block(body if c else orelse)    # statically decided: precise, strong updates
            return
        pre = self.snapshot()
        self.block(body)
        a = self.snapshot()
        self.restore(pre)
        self.block(orelse)
        b = self.snapshot()
        self.join(a, b)

    def stmt(self, s: ast.stmt):
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return  # analyzed separately
        self.scan_calls(s)
        if isinstance(s, ast.Assign):
            st = self.state_of(s.value)
            if isinstance(s.value, ast.Dict) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name):
                self.assign(s.targets[0], VarState({}, st.safe), s.lineno)
                for k, v in zip(s.value.keys, s.value.values):
                    key = _const_key(k) if k is not None else UNKNOWN
                    if key is not UNKNOWN:
                        self._store(f"{s.targets[0].id}[{key!r}]", self.state_of(v))
                    else:
                        self.assign(s.targets[0], VarState(merge(self.taint_of(s.targets[0]), self.taint_of(v))), s.lineno)
                return
            for t in s.targets:
                self.assign(t, st, s.lineno)
        elif isinstance(s, ast.AnnAssign) and s.value is not None:
            self.assign(s.target, self.state_of(s.value), s.lineno)
        if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name) and isinstance(s.value, ast.List):
            self.lists[s.targets[0].id] = [self.state_of(e) for e in s.value.elts]
        if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name) and isinstance(s.value, ast.Call) \
                and dotted(s.value.func).split(".")[-1] in ("urlparse", "urlsplit", "Path", "PurePath", "normpath", "realpath", "abspath") \
                and s.value.args and isinstance(s.value.args[0], ast.Name):
            self.derived[s.targets[0].id] = s.value.args[0].id
        elif isinstance(s, ast.AugAssign):
            cur = self.taint_of(s.target)
            new = self.state_of(s.value)
            cv = UNKNOWN
            a, b = self.const_of(s.target), self.const_of(s.value)
            if a is not UNKNOWN and b is not UNKNOWN and type(s.op) in _BINOPS:
                try:
                    cv = _BINOPS[type(s.op)](a, b)
                except Exception:  # noqa: BLE001
                    cv = UNKNOWN
            self.assign(s.target, VarState(merge(cur, new.taint), new.safe and self.is_safe(s.target), cv), s.lineno)
        elif isinstance(s, (ast.For, ast.AsyncFor)):
            pre = self.snapshot()
            self.loop_exits.append([])
            self.assign(s.target, VarState(self.taint_of(s.iter)), s.lineno)
            self.block(s.body)
            once = self.snapshot()
            self.join(pre, once, *self.loop_exits[-1])
            self.dead = False
            self.assign(s.target, VarState(self.taint_of(s.iter)), s.lineno)
            self.block(s.body)
            exits = self.loop_exits.pop()
            self.join(pre, once, self.snapshot(), *exits)
            self.dead = False
            self.block(s.orelse)
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            for item in s.items:
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, self.state_of(item.context_expr), s.lineno)
            self.block(s.body)
        elif isinstance(s, ast.If):
            self.branch(s.test, s.body, s.orelse)
            for var in self.guarded_vars(s):
                self.env[var] = VarState({}, True)
        elif isinstance(s, ast.While):
            c = self.const_of(s.test)
            if c is UNKNOWN or c:
                pre = self.snapshot()
                self.loop_exits.append([])
                self.block(s.body)
                once = self.snapshot()
                self.join(pre, once, *self.loop_exits[-1])
                self.dead = False
                self.block(s.body)
                exits = self.loop_exits.pop()
                self.join(pre, once, self.snapshot(), *exits)
                self.dead = False
                self.block(s.orelse)
        elif isinstance(s, ast.Try) or s.__class__.__name__ == "TryStar":
            pre = self.snapshot()
            self.block(s.body)
            self.block(s.orelse)
            ok = self.snapshot()
            outs = [ok]
            for h in s.handlers:
                self.join(pre, ok)   # an exception may happen anywhere in the body
                self.dead = False
                self.block(h.body)
                outs.append(self.snapshot())
            self.join(*outs)
            if s.finalbody:
                was_dead = self.dead
                self.dead = False
                self.block(s.finalbody)
                self.dead = was_dead or self.dead
        elif isinstance(s, ast.Match):
            subj = self.const_of(s.subject)
            pre = self.snapshot()
            outs, exhaustive = [], False
            for c in s.cases:
                m = self._case_matches(c.pattern, subj) if subj is not UNKNOWN else None
                if m is False:
                    continue
                self.restore(pre)
                self.block(c.body)
                outs.append(self.snapshot())
                if m is True or (isinstance(c.pattern, ast.MatchAs) and c.pattern.pattern is None and c.guard is None):
                    exhaustive = True
                    break
            if not exhaustive:
                outs.append(pre)
            self.join(*outs) if outs else self.restore(pre)
        elif isinstance(s, ast.Return):
            if s.value is not None:
                t = self.taint_of(s.value)
                self.return_taint.append(t)
                if self.func and self.func.is_route:
                    self.check_xss_return(s.value, t)
            self.dead = True
        elif isinstance(s, ast.Raise):
            self.dead = True
        elif isinstance(s, (ast.Continue, ast.Break)):
            if self.loop_exits:
                self.loop_exits[-1].append(self.snapshot())
            self.dead = True
        elif isinstance(s, ast.Expr) and isinstance(s.value, ast.Call) and isinstance(s.value.func, ast.Attribute):
            self.container_mutation(s.value)

    def container_mutation(self, call: ast.Call):
        base = dotted(call.func.value)
        attr = call.func.attr
        if not base or isinstance(call.func.value, ast.Call):
            return
        lst = self.lists.get(base)
        if lst is not None:
            if attr == "append" and len(call.args) == 1:
                lst.append(self.state_of(call.args[0]))
            elif attr == "insert" and len(call.args) == 2 and isinstance(self.const_of(call.args[0]), int):
                lst.insert(self.const_of(call.args[0]), self.state_of(call.args[1]))
            elif attr == "pop" and len(call.args) <= 1:
                i = self.const_of(call.args[0]) if call.args else -1
                if isinstance(i, int) and -len(lst) <= i < len(lst):
                    lst.pop(i)
                else:
                    self.lists[base] = None
            elif attr in ("clear",):
                lst.clear()
            else:
                self.lists[base] = None
        elif base in self.lists:
            pass
        if attr == "set" and len(call.args) == 3:      # ConfigParser.set(section, key, value)
            k1, k2 = _const_key(call.args[0]), _const_key(call.args[1])
            if k1 is not UNKNOWN and k2 is not UNKNOWN:
                self._store(f"{base}[{k1!r},{k2!r}]", self.state_of(call.args[2]))
                return
        if attr in CONTAINER_MUTATORS or attr == "set":
            t = merge(*[self.taint_of(a) for a in call.args], *[self.taint_of(k.value) for k in call.keywords])
            if t:
                old = self.env.get(base, VarState())
                self.env[base] = VarState(merge(old.taint, extend(t, f"{self.ctx.relpath}:{call.lineno}: {self.ctx.line(call.lineno)[:90]}")), False)

    def guarded_vars(self, node: ast.If) -> list[str]:
        """Recognise validate-or-replace / validate-or-abort idioms, e.g.
        `if not url.startswith("/"): url = "/"` or `if col not in ALLOWED: abort(400)`."""
        if node.orelse or self.const_of(node.test) is not UNKNOWN:
            return []
        test_names = {n.id for n in ast.walk(node.test) if isinstance(n, ast.Name)}
        validates = any(isinstance(n, ast.Compare) and any(isinstance(o, (ast.In, ast.NotIn)) for o in n.ops)
                        for n in ast.walk(node.test)) or \
            any(isinstance(n, ast.Call) and dotted(n.func).split(".")[-1] in self.VALIDATING_CALLS for n in ast.walk(node.test))
        if not validates:
            return []
        if _ends_with_exit(node.body):
            names = set(test_names) | {self.derived[v] for v in test_names if v in self.derived}
            return [v for v in names if v in self.env and (self.env[v].taint or any(k.startswith(v + "[") for k in self.env))]
        out = []
        for b in node.body:
            if isinstance(b, ast.Assign) and len(b.targets) == 1 and isinstance(b.targets[0], ast.Name) \
                    and b.targets[0].id in test_names and self.is_safe(b.value):
                out.append(b.targets[0].id)
            else:
                return []
        return out

    # ---------- sinks ----------
    def scan_calls(self, s: ast.stmt):
        """Check every call that belongs to this statement itself (not to nested blocks)."""
        if isinstance(s, (ast.If, ast.While, ast.Assert)):
            roots = [s.test]
        elif isinstance(s, (ast.For, ast.AsyncFor)):
            roots = [s.iter]
        elif isinstance(s, (ast.With, ast.AsyncWith)):
            roots = [i.context_expr for i in s.items]
        elif isinstance(s, (ast.Expr, ast.Return, ast.AugAssign, ast.AnnAssign, ast.Assign)):
            roots = [s.value] if s.value is not None else []
        elif isinstance(s, ast.Raise):
            roots = [s.exc] if s.exc is not None else []
        elif isinstance(s, ast.Match):
            roots = [s.subject]
        else:
            roots = []
        nodes, stack = [], list(roots)
        while stack:
            n = stack.pop()
            if isinstance(n, ast.Lambda):
                continue
            if isinstance(n, ast.IfExp):
                c = self.const_of(n.test)
                if c is not UNKNOWN:
                    stack.append(n.body if c else n.orelse)
                    continue
            if isinstance(n, ast.Call):
                nodes.append(n)
            stack.extend(ast.iter_child_nodes(n))
        for call in sorted(nodes, key=lambda c: (c.lineno, c.col_offset)):
            self.check_call(call)
        if isinstance(s, ast.Assign) and isinstance(s.value, ast.Call) and len(s.targets) == 1:
            q = self.ctx.qual(s.value.func)
            if q.split(".")[-1] == "XMLParser" and _truthy_const(_kw(s.value, "resolve_entities")):
                self.xxe_parsers.add(dotted(s.targets[0]))
            if q in ("xml.sax.make_parser", "make_parser") and False:
                pass

    def hit(self, category: str, rule_id: str, node: ast.AST, message: str, taint: Taint, severity=None):
        taint = for_cat(taint, category)
        line = getattr(node, "lineno", 0)
        if self.mode == "summary":
            for k, trace in taint.items():
                if k[0] == "param":
                    h = SinkHit(category, rule_id, self.ctx.relpath, line, self.ctx.line(line), self.fname,
                                message, trace + (f"sink at {self.ctx.relpath}:{line}: {self.ctx.line(line)[:90]}",),
                                severity, bool(self.func and self.func.is_route))
                    self.func.sinks.append((k[1], h))
            return
        srcs = {k: v for k, v in taint.items() if k[0] == "src"}
        if not srcs:
            return
        trace = min(srcs.values(), key=len)
        trace = trace + (f"sink at {self.ctx.relpath}:{line}: {self.ctx.line(line)[:90]}",)
        self.engine.report(self.ctx, rule_id, category, node, message, trace, self.fname,
                           confidence="high", severity=severity, route=bool(self.func and self.func.is_route))

    def report_pattern(self, rule_id, node, message, severity=None, confidence="high"):
        if self.mode == "main":
            self.engine.report(self.ctx, rule_id, meta(rule_id)["category"], node, message, (), self.fname,
                               confidence=confidence, severity=severity, route=bool(self.func and self.func.is_route))

    def tainted(self, t: Taint, cat: Optional[str] = None) -> bool:
        t = for_cat(t, cat)
        return has_source(t) if self.mode == "main" else any(k[0] == "param" for k in t)

    def check_call(self, call: ast.Call):
        q = self.ctx.qual(call.func)
        short = q.split(".")[-1] if q else ""
        arg0 = call.args[0] if call.args else None
        t0 = self.taint_of(arg0) if arg0 is not None else {}

        # --- inter-procedural: calls into project functions with known sink summaries
        callee = self.engine.resolve(self.ctx, call, self.func)
        if callee is not None and callee.sinks:
            args = self.bind_args(call, callee)
            for idx, h in callee.sinks:
                if idx in args:
                    at = for_cat(self.taint_of(args[idx]), h.category)
                    if self.tainted(at):
                        step = f"{self.ctx.relpath}:{call.lineno}: passed to {callee.qualname}() — {self.ctx.line(call.lineno)[:80]}"
                        if self.mode == "summary":
                            for k, tr in at.items():
                                if k[0] == "param":
                                    self.func.sinks.append((k[1], SinkHit(h.category, h.rule_id, h.file, h.line, h.snippet,
                                                                          h.function, h.message, tr + (step,) + h.trace[1:], h.severity, h.route)))
                        else:
                            srcs = [v for k, v in at.items() if k[0] == "src"]
                            trace = min(srcs, key=len) + (step,) + h.trace[1:]
                            self.engine.report_hit(h, trace, route=bool(self.func and self.func.is_route) or h.route)

        # --- SQL injection
        if (short in SQL_METHODS and isinstance(call.func, ast.Attribute)) or q in SQL_FUNCS:
            if arg0 is not None:
                if self.tainted(t0, "sqli"):
                    self.hit("sqli", "PY-SQLI-TAINT", call, "User-controlled data is concatenated into a SQL statement.", t0)
                elif self.mode == "main" and not t0 and _is_string_building(arg0) and not self.is_safe(arg0) and self.has_unknown_input(arg0):
                    self.report_pattern("PY-SQLI-FORMAT", call, "SQL statement is built with string formatting from non-constant values.",
                                        severity="medium", confidence="low")
                elif self.mode == "main" and not t0 and isinstance(arg0, ast.Name) and not self.is_safe(arg0) and self.env.get(arg0.id) is not None \
                        and self._var_built_from_strings(arg0.id):
                    self.report_pattern("PY-SQLI-FORMAT", call, "SQL statement variable is built with string formatting from non-constant values.",
                                        severity="medium", confidence="low")
        # --- command injection
        if q in CMD_FUNCS and arg0 is not None:
            if self.tainted(t0, "cmdi"):
                self.hit("cmdi", "PY-CMDI-TAINT", call, "User-controlled data reaches a shell command.", t0)
            elif self.mode == "main" and not t0 and not self.is_safe(arg0) and self.has_unknown_input(arg0):
                self.report_pattern("PY-CMDI-SHELL", call, "Shell command built from non-constant data.", severity="medium", confidence="low")
        if q in SUBPROCESS and arg0 is not None:
            shell = _truthy_const(_kw(call, "shell"))
            first = arg0.elts[0] if isinstance(arg0, (ast.List, ast.Tuple)) and arg0.elts else None
            shell_c = self.const_of(first) if first is not None else UNKNOWN
            shell_list = isinstance(arg0, ast.Name) and self._list_runs_shell(arg0.id)
            if (shell or shell_list or (isinstance(shell_c, str) and shell_c.split("/")[-1] in {"sh", "bash", "cmd.exe", "cmd", "zsh"})) \
                    and self.tainted(t0, "cmdi"):
                self.hit("cmdi", "PY-CMDI-TAINT", call, "User-controlled data reaches a shell (shell=True or sh -c).", t0)
            elif first is not None and self.tainted(self.taint_of(first), "cmdi"):
                self.hit("cmdi", "PY-CMDI-TAINT", call, "User controls the executable launched by subprocess.", self.taint_of(first))
            elif shell and self.mode == "main" and not t0 and not self.is_safe(arg0) and self.has_unknown_input(arg0):
                self.report_pattern("PY-CMDI-SHELL", call, "subprocess called with shell=True on a non-constant command.", severity="medium", confidence="low")
        # --- code injection
        if q in EVAL_FUNCS and isinstance(call.func, ast.Name) and arg0 is not None:
            if self.tainted(t0, "code-injection"):
                self.hit("code-injection", "PY-CODE-EVAL", call, f"User-controlled data is executed by {q}().", t0)
            elif self.mode == "main" and not t0 and not self.is_safe(arg0) and self.has_unknown_input(arg0):
                self.report_pattern("PY-CODE-EVAL", call, f"{q}() on a non-constant value.", severity="medium", confidence="low")
        # --- deserialization
        if q in PICKLE_FUNCS:
            if self.tainted(t0, "deserialization"):
                self.hit("deserialization", "PY-DESER-PICKLE", call, f"Untrusted data deserialized with {q}().", t0)
            elif self.mode == "main" and not t0 and self.has_unknown_input(arg0 if arg0 is not None else call):
                self.report_pattern("PY-DESER-PICKLE", call, f"{q}() can execute arbitrary code if the data is attacker controlled.",
                                    severity="medium", confidence="medium")
        if q in YAML_FUNCS:
            loader = _kw(call, "Loader") or (call.args[1] if len(call.args) > 1 else None)
            lname = dotted(loader) if loader is not None else ""
            if not (q in {"yaml.load", "yaml.load_all"} and lname.split(".")[-1] in {"SafeLoader", "CSafeLoader", "BaseLoader"}):
                if self.tainted(t0, "deserialization"):
                    self.hit("deserialization", "PY-DESER-YAML", call, "Untrusted YAML parsed with an unsafe loader.", t0)
                elif self.mode == "main":
                    self.report_pattern("PY-DESER-YAML", call, "yaml.load without SafeLoader allows arbitrary object construction.",
                                        severity="high", confidence="high")
        # --- path traversal
        if (q in PATH_FUNCS or short == "send_file") and arg0 is not None and self.tainted(t0, "path-traversal"):
            self.hit("path-traversal", "PY-PATH-TRAVERSAL", call, "User-controlled file path used in a filesystem operation.", t0)
        if short in PATH_METHODS and isinstance(call.func, ast.Attribute) and q not in PATH_FUNCS:
            tv = self.taint_of(call.func.value)
            if self.tainted(tv, "path-traversal") and not (short in {"exists", "stat"} and q.startswith("os.")):
                self.hit("path-traversal", "PY-PATH-TRAVERSAL", call, "User-controlled path used in a filesystem operation.", tv)
        # --- SSRF
        if q in SSRF_FUNCS:
            url = _kw(call, "url") or (call.args[1] if q.endswith(".request") and len(call.args) > 1 else arg0)
            tu = self.taint_of(url)
            if url is not None and self.tainted(tu, "ssrf"):
                self.hit("ssrf", "PY-SSRF", call, "Server makes an HTTP request to a user-controlled URL.", tu)
        # --- open redirect
        if (q in REDIRECT_FUNCS or short == "redirect") and arg0 is not None and self.tainted(t0, "open-redirect"):
            self.hit("open-redirect", "PY-OPEN-REDIRECT", call, "Redirect target is user controlled.", t0)
        # --- SSTI
        if (q in SSTI_FUNCS or short == "render_template_string") and arg0 is not None:
            if self.tainted(t0, "ssti"):
                self.hit("ssti", "PY-SSTI", call, "User-controlled data is compiled as a template.", t0)
            elif self.mode == "main" and not t0 and short == "render_template_string" and not self.is_safe(arg0) and self.has_unknown_input(arg0):
                self.report_pattern("PY-SSTI", call, "Template compiled from a non-constant string.", severity="medium", confidence="low")
        # --- XXE
        if q in XML_PARSE_FUNCS and arg0 is not None:
            parser = _kw(call, "parser") or (call.args[1] if len(call.args) > 1 else None)
            pname = dotted(parser) if parser is not None else ""
            if pname in self.xxe_parsers and self.tainted(t0, "xxe"):
                self.hit("xxe", "PY-XXE", call, "Untrusted XML parsed with external entity resolution enabled.", t0)
        if short == "parse" and isinstance(call.func, ast.Attribute) and dotted(call.func.value) in self.xxe_parsers \
                and arg0 is not None and self.tainted(t0, "xxe"):
            self.hit("xxe", "PY-XXE", call, "Untrusted XML parsed with external entity resolution enabled.", t0)
        if short == "setFeature" and isinstance(call.func, ast.Attribute) and len(call.args) == 2 \
                and re.search(r"external_(ges|pes)", ast.unparse(call.args[0])) and _truthy_const(call.args[1]):
            self.xxe_parsers.add(dotted(call.func.value))
        if short == "XMLParser" and _truthy_const(_kw(call, "resolve_entities")):
            self.report_pattern("PY-XXE", call, "XMLParser created with resolve_entities=True.", severity="medium", confidence="medium")
        # --- XPath injection
        if isinstance(call.func, ast.Attribute) and arg0 is not None and (
                short == "xpath" or q in {"lxml.etree.XPath", "etree.XPath", "elementpath.select"} or
                short in {"findall", "iterfind", "findtext"} and not self.tainted(self.taint_of(call.func.value))):
            target = call.args[1] if q == "elementpath.select" and len(call.args) > 1 else arg0
            tt = self.taint_of(target)
            if self.tainted(tt, "xpathi"):
                self.hit("xpathi", "PY-XPATH-INJECTION", call, "User-controlled data concatenated into an XPath expression.", tt)
        # --- LDAP injection
        if isinstance(call.func, ast.Attribute) and not q.startswith("re.") and short in {"search", "search_s", "search_st", "search_ext", "search_ext_s", "paged_search"}:
            idx = 2 if short.startswith(("search_s", "search_st", "search_ext")) else 1
            flt = _kw(call, "search_filter") or _kw(call, "filterstr") or (call.args[idx] if len(call.args) > idx else None)
            if flt is not None and len(call.args) >= 2:
                tf = self.taint_of(flt)
                if self.tainted(tf, "ldapi"):
                    self.hit("ldapi", "PY-LDAP-INJECTION", call, "User-controlled data concatenated into an LDAP search filter.", tf)
        # --- XSS via response helpers
        if q in RESPONSE_FUNCS and arg0 is not None and self.tainted(t0, "xss") and not isinstance(arg0, ast.Call):
            self.hit("xss", "PY-XSS-RESPONSE", call, "User-controlled data written into an HTML response without escaping.", t0)
        # --- session trust boundary (session.update / setdefault)
        if isinstance(call.func, ast.Attribute) and dotted(call.func.value).split(".")[-1].lower().endswith("session") \
                and short in {"update", "setdefault", "__setitem__"}:
            ta = merge(*[self.taint_of(a) for a in call.args])
            if self.tainted(ta, "trust-boundary"):
                self.hit("trust-boundary", "PY-TRUST-BOUNDARY", call, "Untrusted request data stored in the server-side session.", ta)
        if self.mode == "main":
            self.pattern_rules(call, q, short)

    def _list_runs_shell(self, name: str) -> bool:
        node = self.func.node if self.func else self.ctx.tree
        for n in ast.walk(node):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and dotted(n.func.value) == name \
                    and n.func.attr in ("append", "insert") and n.args:
                v = n.args[-1]
                if isinstance(v, ast.Constant) and str(v.value) in ("-c", "/c", "/C"):
                    return True
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in n.targets) \
                    and isinstance(n.value, ast.List) and any(isinstance(e, ast.Constant) and e.value in ("-c", "/c") for e in n.value.elts):
                return True
        return False

    def _var_built_from_strings(self, name: str) -> bool:
        node = self.func.node if self.func else self.ctx.tree
        for n in ast.walk(node):
            if isinstance(n, (ast.Assign, ast.AugAssign)):
                targets = n.targets if isinstance(n, ast.Assign) else [n.target]
                if any(isinstance(t, ast.Name) and t.id == name for t in targets) and _is_string_building(n.value) \
                        or (isinstance(n, ast.AugAssign) and isinstance(n.target, ast.Name) and n.target.id == name):
                    if not self.is_safe(n.value):
                        return True
        return False

    def check_xss_return(self, value: ast.AST, t: Taint):
        t = for_cat(t, "xss")
        if self.mode == "summary" or not has_source(t):
            return
        if isinstance(value, ast.Call):
            return  # jsonify(...), render_template(...) etc. are handled by their own rules
        if _is_string_building(value) or isinstance(value, ast.Name):
            sev = "high" if _contains_html(value) or isinstance(value, ast.Name) else "medium"
            self.hit("xss", "PY-XSS-RESPONSE", value, "Route returns user-controlled data as HTML without escaping (reflected XSS).", t, severity=sev)

    # ---------- non-taint pattern rules ----------
    def context_words(self, call: ast.Call) -> str:
        return " ".join([self.fname, self.ctx.line(call.lineno)])

    def pattern_rules(self, call: ast.Call, q: str, short: str):
        strict = self.engine.strict
        weak_new = q == "hashlib.new" and call.args and isinstance(call.args[0], ast.Constant) and \
            str(call.args[0].value).lower() in {"md5", "sha1", "md4", "md5-sha1"}
        if q in {"hashlib.md5", "hashlib.sha1"} or weak_new or q in {"Crypto.Hash.MD5.new", "Crypto.Hash.SHA1.new", "cryptography.hazmat.primitives.hashes.MD5", "cryptography.hazmat.primitives.hashes.SHA1"}:
            ufs = _kw(call, "usedforsecurity")
            if not _false_const(ufs):
                if SECURITY_WORDS.search(self.context_words(call)):
                    self.report_pattern("PY-WEAK-HASH", call, "Weak hash (MD5/SHA-1) used in a security context such as password hashing.", severity="high")
                elif strict:
                    self.report_pattern("PY-WEAK-HASH", call, "Weak hash algorithm (MD5/SHA-1).", severity="medium", confidence="medium")
        if q.startswith("random.") and "SystemRandom" not in q and short not in {"seed", "getstate", "setstate", "SystemRandom"}:
            if SECURITY_WORDS.search(self.context_words(call)):
                self.report_pattern("PY-INSECURE-RANDOM", call, "Non-cryptographic PRNG used to generate a security-sensitive value.")
            elif strict:
                self.report_pattern("PY-INSECURE-RANDOM", call, "Non-cryptographic PRNG (random module).", severity="low", confidence="medium")
        if short == "run" and _truthy_const(_kw(call, "debug")):
            self.report_pattern("PY-FLASK-DEBUG", call, "Application started with debug=True (interactive debugger allows code execution).")
        v = _kw(call, "verify")
        if _false_const(v) and short != "decode":
            self.report_pattern("PY-TLS-VERIFY", call, "TLS certificate verification disabled (verify=False).")
        if q in {"ssl._create_unverified_context"}:
            self.report_pattern("PY-TLS-VERIFY", call, "Unverified SSL context created.")
        if q in {"jwt.decode"}:
            opts = _kw(call, "options")
            bad = False
            if isinstance(opts, ast.Dict):
                for k, val in zip(opts.keys, opts.values):
                    if isinstance(k, ast.Constant) and k.value == "verify_signature" and _false_const(val):
                        bad = True
            if _false_const(v):
                bad = True
            algs = _kw(call, "algorithms")
            if algs is not None and "none" in ast.unparse(algs).lower():
                bad = True
            if bad:
                self.report_pattern("PY-JWT-NOVERIFY", call, "JWT decoded without signature verification.")
        if short == "set_cookie":
            secure, httponly = _kw(call, "secure"), _kw(call, "httponly")
            if _false_const(secure):
                self.report_pattern("PY-COOKIE-INSECURE", call, "Cookie explicitly set without the Secure flag (sent over plain HTTP).", severity="medium")
            else:
                name = ast.unparse(call.args[0]) if call.args else ""
                if SECURITY_WORDS.search(name) and not (_truthy_const(httponly) and _truthy_const(secure)):
                    self.report_pattern("PY-COOKIE-INSECURE", call, "Sensitive cookie set without Secure/HttpOnly flags.")
        if q == "tempfile.mktemp":
            self.report_pattern("PY-TEMPFILE", call, "tempfile.mktemp is race-prone.")


class PythonTaintEngine:
    def __init__(self, strict: bool = False):
        self.modules: dict[str, ModuleContext] = {}
        self.functions: dict[str, list[FuncInfo]] = {}
        self.findings: list[Finding] = []
        self.strict = strict
        self.keyed: set = set()
        self._seen: dict = {}

    # ---------- project indexing ----------
    def add_file(self, relpath: str, source: str) -> bool:
        try:
            tree = ast.parse(source)
        except (SyntaxError, ValueError):
            return False
        ctx = ModuleContext(relpath, source, tree)
        self.modules[relpath] = ctx
        self._index(ctx, tree.body, prefix="")
        return True

    def _index(self, ctx, body, prefix, in_class=False):
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                params = [a.arg for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
                is_route = any(isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr in ROUTE_DECORATORS
                               for d in node.decorator_list)
                fi = FuncInfo(node.name, f"{prefix}{node.name}", ctx.relpath, node, params,
                              in_class and bool(params) and params[0] in ("self", "cls"), is_route)
                self.functions.setdefault(node.name, []).append(fi)
                self._index(ctx, node.body, prefix=f"{prefix}{node.name}.")
            elif isinstance(node, ast.ClassDef):
                self._index(ctx, node.body, prefix=f"{prefix}{node.name}.", in_class=True)

    def resolve(self, ctx: ModuleContext, call: ast.Call, current: Optional[FuncInfo]) -> Optional[FuncInfo]:
        f = call.func
        name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
        if not name or name not in self.functions:
            return None
        cands = self.functions[name]
        if isinstance(f, ast.Name):
            same = [c for c in cands if c.module == ctx.relpath and not c.is_method]
            if same:
                return same[0]
            mod = ctx.imported_from.get(name)
            if mod:
                stem = mod.split(".")[-1]
                for c in cands:
                    if c.module.rsplit("/", 1)[-1][:-3] == stem:
                        return c
            return cands[0] if len(cands) == 1 else None
        # attribute call: module.func(...) or obj.method(...)
        base = dotted(f.value)
        q = ctx.qual(f.value)
        stems = {base.split(".")[-1], q.split(".")[-1]}
        if base in ctx.aliases or q != base or "." in base:
            for c in cands:
                if c.module.rsplit("/", 1)[-1][:-3] in stems and not c.is_method:
                    return c
        if base in ("self", "cls") and current:
            cls_prefix = current.qualname.rsplit(".", 1)[0] + "."
            for c in cands:
                if c.qualname.startswith(cls_prefix) and c.module == current.module:
                    return c
        methods = [c for c in cands if c.is_method]
        if len(methods) == 1 and len(cands) == 1:
            return methods[0]
        if methods and len({(c.module, tuple(sorted(c.returns.items()))) for c in methods}) == 1 and all(not c.sinks for c in methods):
            return methods[0]  # polymorphic implementations with identical summaries
        return None

    # ---------- analysis ----------
    def analyze(self) -> list[Finding]:
        allf = [f for fs in self.functions.values() for f in fs]
        for _ in range(4):  # summaries to a fixpoint (bounded)
            before = [(len(f.sinks), tuple(sorted(f.returns.items()))) for f in allf]
            for f in allf:
                f.sinks.clear()
                FunctionAnalyzer(self, self.modules[f.module], f, "summary").run(f.node.body)
                seen, uniq = set(), []
                for idx, h in f.sinks:
                    key = (idx, h.file, h.line, h.rule_id)
                    if key not in seen:
                        seen.add(key); uniq.append((idx, h))
                f.sinks[:] = uniq
            if [(len(f.sinks), tuple(sorted(f.returns.items()))) for f in allf] == before:
                break
        for ctx in self.modules.values():
            FunctionAnalyzer(self, ctx, None, "main").run(ctx.tree.body)
            self._module_patterns(ctx)
        for f in allf:
            FunctionAnalyzer(self, self.modules[f.module], f, "main").run(f.node.body)
        return self.findings

    def _module_patterns(self, ctx: ModuleContext):
        for node in ast.walk(ctx.tree):
            targets, value = [], None
            if isinstance(node, ast.Assign):
                targets, value = node.targets, node.value
            elif isinstance(node, ast.AnnAssign):
                targets, value = [node.target], node.value
            for t in targets:
                name = t.attr if isinstance(t, ast.Attribute) else t.id if isinstance(t, ast.Name) else \
                    (t.slice.value if isinstance(t, ast.Subscript) and isinstance(t.slice, ast.Constant) else "")
                name = str(name)
                if name in {"WTF_CSRF_ENABLED", "CSRF_ENABLED"} and _false_const(value):
                    self.report(ctx, "PY-CSRF-DISABLED", "csrf", node, "CSRF protection is disabled.", (), "<module>", "high")
                if name in {"DEBUG"} and isinstance(value, ast.Constant) and value.value is True and \
                        re.search(r"(settings|config)", ctx.relpath, re.I):
                    self.report(ctx, "PY-FLASK-DEBUG", "debug", node, "DEBUG enabled in configuration.", (), "<module>", "medium", severity="low")
                self._check_secret(ctx, name, value, node)
            if isinstance(node, ast.Call):
                for k in node.keywords:
                    if k.arg:
                        self._check_secret(ctx, k.arg, k.value, node)
            if isinstance(node, ast.Dict):
                for k, v in zip(node.keys, node.values):
                    if isinstance(k, ast.Constant) and isinstance(k.value, str):
                        self._check_secret(ctx, k.value, v, k)

    def _check_secret(self, ctx, name, value, node):
        if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
            return
        val = value.value
        if not SECRET_NAME_RE.search(name.replace("-", "_")) or len(val) < 6 or PLACEHOLDER_RE.match(val):
            return
        if re.fullmatch(r"[A-Za-z_]+", val) and len(val) < 10:  # identifiers like "password_hash"
            return
        if "/" in val and " " not in val and val.startswith(("/", "http")):
            return
        from .secrets import entropy
        conf = "high" if entropy(val) > 3.0 else "medium"
        self.report(ctx, "PY-HARDCODED-SECRET", "secrets", node, f"Hardcoded credential assigned to '{name}'.", (), "<module>", conf)

    # ---------- reporting ----------
    def report(self, ctx, rule_id, category, node, message, trace, function, confidence="high", severity=None, route=False):
        line = getattr(node, "lineno", 0)
        h = SinkHit(category, rule_id, ctx.relpath, line, ctx.line(line), function, message, tuple(trace), severity, route)
        self.report_hit(h, tuple(trace), route, confidence)

    def report_hit(self, h: SinkHit, trace: tuple, route=False, confidence=None):
        confidence = confidence or ("high" if trace else "low")
        m = meta(h.rule_id)
        sev = h.severity or m["severity"]
        if trace and any("local input" in t for t in trace[:1]):
            confidence = "medium"
        key = (h.file, h.line, h.category)
        f = Finding(rule_id=h.rule_id, title=m["title"], severity=sev, confidence=confidence, file=h.file, line=h.line,
                    message=h.message, cwe=m["cwe"], owasp=m["owasp"], category=h.category, language="python",
                    snippet=h.snippet, engine="taint" if trace else "rule", function=h.function, trace=list(trace),
                    extra={"route": route})
        prev = self._seen.get(key)
        rank = {"high": 3, "medium": 2, "low": 1}
        if prev is not None:
            if rank[confidence] > rank[prev.confidence] or (rank[confidence] == rank[prev.confidence] and len(trace) > len(prev.trace)):
                self.findings[self.findings.index(prev)] = f
                self._seen[key] = f
            return
        self._seen[key] = f
        self.findings.append(f)
