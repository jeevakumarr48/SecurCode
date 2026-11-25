"""Extended detection rules (PYSEC011+ and JSSEC006+).

Python rules walk the AST with import-alias resolution. JavaScript and
TypeScript rules are lexical: comments and string contents are masked
first so matches inside them are ignored, and string literals are inspected
only where a rule needs their value. Lexical rules cannot follow data flow
through variables, aliases or other files; see docs/scanner for limits.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from .javascript import JAVASCRIPT_EXTENSIONS, TYPESCRIPT_EXTENSIONS, _mask_comments_and_strings
from .rules import RULES

SECRET_NAME = re.compile(r"(?:^|_)(?:password|passwd|pwd|secret|token|api_?key|apikey|otp|nonce|salt|session_?key|private_?key)s?$", re.I)
SECRET_WORD = re.compile(r"password|passwd|secret|token|api_?key|apikey|otp|nonce|salt|credential", re.I)
KNOWN_SECRET = re.compile(
    r"(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,}"
    r"|xox[abpr]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{20,}|-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)"
)
REQUEST_ATTR = re.compile(r"(?:^|\.)request\.(?:args|form|values|GET|POST|query_params|json|data)\b")
LOCAL_HOSTS = ("localhost", "127.0.0.1", "0.0.0.0", "[::1]", "example.com", "example.org")  # noqa: S104 - detection data


def _finding(rule_id: str, language: str, filename: str, line: int, column: int | None, detail: str | None = None) -> dict:
    rule = RULES[rule_id]
    finding = {
        "severity": rule.severity,
        "confidence": rule.confidence,
        "test_id": rule_id,
        "language": language,
        "filename": filename,
        "line_number": line,
        "description": detail or rule.description,
        "remediation": rule.remediation,
        "cwe": rule.cwe,
    }
    if column is not None:
        finding["column_number"] = column
    return finding


# --- Python ---------------------------------------------------------------------------

class _PythonRules(ast.NodeVisitor):
    def __init__(self, filename: str, source: str):
        self.filename = filename
        self.source = source
        self.findings: list[dict] = []
        self.aliases: dict[str, str] = {}

    def _emit(self, rule_id: str, node: ast.AST, detail: str | None = None) -> None:
        self.findings.append(_finding(rule_id, "Python", self.filename, getattr(node, "lineno", 1),
                                      getattr(node, "col_offset", 0) + 1, detail))

    def _name(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            base = self._name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Call):
            return self._name(node.func) + "()"
        return ""

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name if alias.asname else alias.name.split(".")[0]
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module:
            for alias in node.names:
                self.aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
        self.generic_visit(node)

    @staticmethod
    def _kw(node: ast.Call, name: str):
        for keyword in node.keywords:
            if keyword.arg == name:
                return keyword.value
        return None

    def _mentions_request(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            name = self._name(child) if isinstance(child, (ast.Attribute, ast.Name)) else ""
            if REQUEST_ATTR.search(name):
                return True
        return False

    def visit_Call(self, node: ast.Call) -> None:
        name = self._name(node.func)
        short = name.rsplit(".", 1)[-1]

        if name == "tempfile.mktemp":
            self._emit("PYSEC011", node)

        if name in {"hashlib.md5", "hashlib.sha1"} or (
            name == "hashlib.new" and node.args and isinstance(node.args[0], ast.Constant)
            and str(node.args[0].value).lower() in {"md5", "sha1", "md4"}
        ):
            flag = self._kw(node, "usedforsecurity")
            if not (isinstance(flag, ast.Constant) and flag.value is False):
                self._emit("PYSEC012", node)

        lowered = name.lower()
        if any(cipher in lowered for cipher in ("cipher.des.new", "cipher.arc4.new", "cipher.blowfish.new", "cipher.des3.new",
                                                "algorithms.tripledes", "algorithms.arc4", "algorithms.blowfish")):
            self._emit("PYSEC013", node)
        if name.endswith(".new") and any(
            isinstance(arg, ast.Attribute) and arg.attr == "MODE_ECB" for arg in [*node.args, *[k.value for k in node.keywords]]
        ):
            self._emit("PYSEC013", node, "Block cipher used in ECB mode, which leaks plaintext patterns.")
        if name.endswith("modes.ECB"):
            self._emit("PYSEC013", node, "Block cipher used in ECB mode, which leaks plaintext patterns.")

        verify = self._kw(node, "verify")
        if isinstance(verify, ast.Constant) and verify.value is False and (
            name.startswith(("requests.", "httpx.", "aiohttp.")) or short in {"get", "post", "put", "patch", "delete", "request", "Client", "AsyncClient", "Session"}
        ):
            self._emit("PYSEC015", node)
        if name in {"ssl._create_unverified_context", "ssl._create_stdlib_context"}:
            self._emit("PYSEC015", node)

        if short == "run" and isinstance(self._kw(node, "debug"), ast.Constant) and self._kw(node, "debug").value is True:
            self._emit("PYSEC016", node)
        host = self._kw(node, "host")
        if short == "run" and isinstance(host, ast.Constant) and host.value == "0.0.0.0":  # noqa: S104
            self._emit("PYSEC026", node)

        if short in {"redirect", "RedirectResponse", "HttpResponseRedirect"} and node.args and self._mentions_request(node.args[0]):
            self._emit("PYSEC017", node)

        if name.startswith(("requests.", "httpx.", "urllib.request.urlopen")) and node.args:
            target = node.args[0]
            if isinstance(target, ast.Constant) and isinstance(target.value, str) and target.value.startswith("http://") \
                    and not any(host_name in target.value for host_name in LOCAL_HOSTS):
                self._emit("PYSEC019", node)

        if short in {"print", "debug", "info", "warning", "error", "exception", "critical", "log"} and (
            short == "print" or "log" in name.lower()
        ):
            for argument in [*node.args, *[k.value for k in node.keywords]]:
                for child in ast.walk(argument):
                    if isinstance(child, ast.Name) and SECRET_NAME.search(child.id):
                        self._emit("PYSEC020", node)
                        break
                    if isinstance(child, ast.Attribute) and SECRET_NAME.search(child.attr):
                        self._emit("PYSEC020", node)
                        break
                else:
                    continue
                break

        if name in {"jwt.decode"}:
            options = self._kw(node, "options")
            verify_kw = self._kw(node, "verify")
            algorithms = self._kw(node, "algorithms")
            disabled = isinstance(verify_kw, ast.Constant) and verify_kw.value is False
            if isinstance(options, ast.Dict):
                for key, value in zip(options.keys, options.values, strict=False):
                    if isinstance(key, ast.Constant) and key.value == "verify_signature" and isinstance(value, ast.Constant) and value.value is False:
                        disabled = True
            if isinstance(algorithms, (ast.List, ast.Tuple)) and any(
                isinstance(item, ast.Constant) and str(item.value).lower() == "none" for item in algorithms.elts
            ):
                disabled = True
            if disabled:
                self._emit("PYSEC021", node)

        if name == "os.chmod" and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, int):
            if node.args[1].value & 0o002:
                self._emit("PYSEC022", node)

        if short == "extractall" and self._kw(node, "filter") is None and self._kw(node, "members") is None:
            receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
            receiver_name = self._name(receiver) if receiver is not None else ""
            if "zip" not in receiver_name.lower():
                self._emit("PYSEC023", node)

        if short in {"XMLParser"} and isinstance(self._kw(node, "resolve_entities"), ast.Constant) and self._kw(node, "resolve_entities").value is True:
            self._emit("PYSEC024", node)
        if short == "setFeature" and len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) and node.args[1].value is True:
            feature = self._name(node.args[0]) if not isinstance(node.args[0], ast.Constant) else str(node.args[0].value)
            if "external" in feature.lower():
                self._emit("PYSEC024", node)
        self.generic_visit(node)

    def _check_assignment(self, targets, value, node) -> None:
        names = []
        for target in targets:
            if isinstance(target, ast.Name):
                names.append(target.id)
            elif isinstance(target, ast.Attribute):
                names.append(target.attr)
            elif isinstance(target, ast.Subscript) and isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                names.append(target.slice.value)
        for name in names:
            if SECRET_NAME.search(name) and isinstance(value, ast.Call):
                called = self._name(value.func)
                if called.startswith("random.") and called.rsplit(".", 1)[-1] in {
                    "random", "randint", "choice", "choices", "getrandbits", "randrange", "sample"
                }:
                    self._emit("PYSEC014", node)
            if SECRET_NAME.search(name) and isinstance(value, ast.Call) and self._name(value.func).endswith("join"):
                for child in ast.walk(value):
                    if isinstance(child, ast.Call) and self._name(child.func).startswith("random."):
                        self._emit("PYSEC014", node)
                        break
            upper = name.upper()
            if upper == "DEBUG" and isinstance(value, ast.Constant) and value.value is True:
                self._emit("PYSEC016", node)
            if upper in {"SESSION_COOKIE_SECURE", "SESSION_COOKIE_HTTPONLY", "CSRF_COOKIE_SECURE", "WTF_CSRF_ENABLED",
                         "CSRF_ENABLED"} and isinstance(value, ast.Constant) and value.value is False:
                self._emit("PYSEC018", node)
            if upper == "VERIFY_MODE" and isinstance(value, ast.Attribute) and value.attr == "CERT_NONE":
                self._emit("PYSEC015", node)
            if upper == "CHECK_HOSTNAME" and isinstance(value, ast.Constant) and value.value is False:
                self._emit("PYSEC015", node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._check_assignment(node.targets, node.value, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self._check_assignment([node.target], node.value, node)
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str) and KNOWN_SECRET.search(node.value):
            self._emit("PYSEC025", node)


def scan_python_extended(filename: str) -> list[dict]:
    source = Path(filename).read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(source, filename=filename)
    except (SyntaxError, ValueError):
        return []
    visitor = _PythonRules(filename, source)
    visitor.visit(tree)
    return visitor.findings


# --- JavaScript / TypeScript -------------------------------------------------------

REQUEST_DATA = r"req(?:uest)?\s*\.\s*(?:query|params|body|headers|cookies)"
JS_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # (rule, pattern applied to masked source, optional literal check: "nonliteral" | "string_arg" | "")
    ("JSSEC006", re.compile(r"\.\s*(?:innerHTML|outerHTML)\s*(?:\+?=)(?!=)"), "nonliteral_rhs"),
    ("JSSEC006", re.compile(r"\.\s*insertAdjacentHTML\s*\("), "nonliteral_second_arg"),
    ("JSSEC006", re.compile(r"\bdocument\s*\.\s*(?:write|writeln)\s*\("), "nonliteral_first_arg"),
    ("JSSEC007", re.compile(r"\bdangerouslySetInnerHTML\s*="), ""),
    ("JSSEC008", re.compile(r"\b(?:setTimeout|setInterval)\s*\("), "raw_string_follows"),
    ("JSSEC009", re.compile(r"\bcreateHash\s*\("), "weak_hash"),
    ("JSSEC009", re.compile(r"\bcreateCipher\s*\("), ""),
    ("JSSEC009", re.compile(r"\bcreateCipheriv\s*\("), "weak_cipher"),
    ("JSSEC011", re.compile(r"\brejectUnauthorized\s*:\s*false\b"), ""),
    ("JSSEC011", re.compile(r"\bNODE_TLS_REJECT_UNAUTHORIZED\b\s*="), "zero_value"),
    ("JSSEC012", re.compile(r"\bres\s*\.\s*redirect\s*\(\s*(?:\d+\s*,\s*)?" + REQUEST_DATA), ""),
    ("JSSEC012", re.compile(r"\b(?:window\s*\.\s*)?location(?:\s*\.\s*href)?\s*=\s*[^=;\n]*(?:location\s*\.\s*(?:search|hash)|URLSearchParams|searchParams\s*\.\s*get)"), ""),
    ("JSSEC013", re.compile(r"\.\s*(?:query|execute|raw)\s*\("), "template_interpolation"),
    ("JSSEC013", re.compile(r"\.\s*(?:query|execute|raw)\s*\("), "string_concatenation"),
    ("JSSEC014", re.compile(r"\bunserialize\s*\("), ""),
    ("JSSEC015", re.compile(r"\b(?:fs\s*\.\s*)?(?:readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync)\s*\(\s*" + REQUEST_DATA), ""),
    ("JSSEC015", re.compile(r"\bres\s*\.\s*(?:sendFile|download)\s*\(\s*" + REQUEST_DATA), ""),
    ("JSSEC016", re.compile(r"\bconsole\s*\.\s*(?:log|info|debug|warn|error)\s*\([^)\n]*\b[\w.]*(?:password|passwd|secret|token|apiKey|api_key)\b"), ""),
    ("JSSEC017", re.compile(r"\b(?:fetch|axios(?:\s*\.\s*(?:get|post|put|request))?|got|https?\s*\.\s*(?:get|request))\s*\(\s*" + REQUEST_DATA), ""),
    ("JSSEC019", re.compile(r"\bvm\s*\.\s*(?:runInThisContext|runInNewContext|runInContext|compileFunction)\s*\(|\bnew\s+vm\s*\.\s*Script\s*\("), ""),
]
WEAK_HASHES = {"md5", "sha1", "md4", "ripemd160"}
WEAK_CIPHERS = re.compile(r"^(?:des|des-ede|des-ede3|rc4|rc2|bf|blowfish)\b|-ecb$", re.I)
RANDOM_SECRET = re.compile(r"Math\s*\.\s*random\s*\(")
STRING_LITERAL = re.compile(r"([\"'])((?:\\.|(?!\1).)*)\1")


def _skip_ws(source: str, offset: int) -> int:
    while offset < len(source) and source[offset] in " \t\r\n":
        offset += 1
    return offset


def _line_col(source: str, offset: int) -> tuple[int, int]:
    line = source.count("\n", 0, offset) + 1
    return line, offset - source.rfind("\n", 0, offset)


def _literal_at(source: str, offset: int) -> str | None:
    match = STRING_LITERAL.match(source, offset)
    return match.group(2) if match else None


def _next_token_is_literal(source: str, offset: int) -> bool:
    rest = source[offset:offset + 200].lstrip()
    if not rest:
        return False
    if rest[0] in "\"'":
        literal = STRING_LITERAL.match(rest)
        if literal:
            tail = rest[literal.end():].lstrip()
            return not tail or tail[0] in ";,)\n}"
    if rest[0] == "`":
        end = rest.find("`", 1)
        return end > 0 and "${" not in rest[:end]
    return False


def _split_args(source: str, start: int) -> int | None:
    """Return the offset just after the first top-level comma of a call."""
    depth = 0
    index = start
    while index < len(source) and index < start + 2000:
        char = source[index]
        if char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return None
            depth -= 1
        elif char == "," and depth == 0:
            return index + 1
        index += 1
    return None


def scan_javascript_extended(filename: str) -> list[dict]:
    path = Path(filename)
    language = "TypeScript" if path.suffix.lower() in TYPESCRIPT_EXTENSIONS else "JavaScript"
    source = path.read_text(encoding="utf-8", errors="replace")
    masked = _mask_comments_and_strings(source)
    findings: list[dict] = []
    seen: set[tuple[str, int]] = set()

    def emit(rule_id: str, offset: int, detail: str | None = None) -> None:
        line, column = _line_col(source, offset)
        if (rule_id, line) in seen:
            return
        seen.add((rule_id, line))
        findings.append(_finding(rule_id, language, filename, line, column, detail))

    for rule_id, pattern, check in JS_PATTERNS:
        for match in pattern.finditer(masked):
            end = _skip_ws(source, match.end())
            if check == "nonliteral_rhs" and _next_token_is_literal(source, end):
                continue
            if check == "nonliteral_first_arg" and _next_token_is_literal(source, end):
                continue
            if check == "nonliteral_second_arg":
                second = _split_args(source, end)
                if second is None or _next_token_is_literal(source, second):
                    continue
            if check == "raw_string_follows" and source[end:end + 1] not in {"\"", "'", "`"}:
                continue
            if check == "weak_hash":
                literal = _literal_at(source, end)
                if not literal or literal.lower() not in WEAK_HASHES:
                    continue
            if check == "weak_cipher":
                literal = _literal_at(source, end)
                if not literal or not WEAK_CIPHERS.search(literal):
                    continue
            if check == "zero_value":
                if not source[end:end + 3].startswith(("0", "'0'", '"0"')):
                    continue
            if check == "template_interpolation":
                if source[end:end + 1] != "`":
                    continue
                closing = source.find("`", end + 1)
                if closing < 0 or "${" not in source[end:closing]:
                    continue
            if check == "string_concatenation":
                literal = STRING_LITERAL.match(source, end)
                if not literal or not source[literal.end():literal.end() + 20].lstrip().startswith("+"):
                    continue
            emit(rule_id, match.start())

    for line_index, line_text in enumerate(masked.splitlines()):
        if RANDOM_SECRET.search(line_text) and SECRET_WORD.search(line_text):
            offset = sum(len(item) + 1 for item in masked.splitlines()[:line_index]) + RANDOM_SECRET.search(line_text).start()
            emit("JSSEC010", offset)

    for literal in STRING_LITERAL.finditer(source):
        if masked[literal.start()] == " " and source[literal.start()] in "\"'" and KNOWN_SECRET.search(literal.group(2)):
            # Masked quote position means the literal is real code, not inside a comment.
            if _inside_comment(source, literal.start()):
                continue
            emit("JSSEC018", literal.start())
    return findings


def _inside_comment(source: str, offset: int) -> bool:
    line_start = source.rfind("\n", 0, offset) + 1
    prefix = source[line_start:offset]
    if "//" in prefix and prefix.count('"') % 2 == 0 and prefix.count("'") % 2 == 0:
        return True
    last_open = source.rfind("/*", 0, offset)
    return last_open != -1 and source.rfind("*/", 0, offset) < last_open


def scan_extended(filename: str) -> list[dict]:
    suffix = Path(filename).suffix.lower()
    if suffix == ".py":
        return scan_python_extended(filename)
    if suffix in JAVASCRIPT_EXTENSIONS | TYPESCRIPT_EXTENSIONS:
        return scan_javascript_extended(filename)
    return []
