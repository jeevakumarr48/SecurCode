import ast
import re
from .remediation import cwe_for, remediation_for


SECRET_NAME_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)$",
    re.IGNORECASE,
)
PLACEHOLDER_VALUES = {
    "changeme",
    "change-me",
    "example",
    "placeholder",
    "replace-me",
    "your-password",
    "your_secret",
}


def _finding(severity, confidence, test_id, filename, line_number, description):
    return {
        "severity": severity,
        "confidence": confidence,
        "test_id": test_id,
        "language": "Python",
        "filename": filename,
        "line_number": line_number,
        "description": description,
        "remediation": remediation_for(test_id),
        "cwe": cwe_for(test_id),
    }


def _constant_string(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _import_aliases(tree):
    modules = {}
    functions = {}
    monitored = {"subprocess", "os", "pickle", "dill", "marshal", "yaml"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for item in node.names:
                if item.name in monitored:
                    modules[item.asname or item.name.split(".")[0]] = item.name
        elif isinstance(node, ast.ImportFrom) and node.module in monitored:
            for item in node.names:
                functions[item.asname or item.name] = (node.module, item.name)
    return modules, functions


def _call_is(node, module, attributes, module_aliases, function_aliases):
    if isinstance(node.func, ast.Name):
        return function_aliases.get(node.func.id) in {
            (module, attribute) for attribute in attributes
        }
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
        imported_module = module_aliases.get(node.func.value.id, node.func.value.id)
        return imported_module == module and node.func.attr in attributes
    return False


def _has_true_keyword(node, keyword):
    return any(
        item.arg == keyword
        and isinstance(item.value, ast.Constant)
        and item.value.value is True
        for item in node.keywords
    )


def _dynamic_sql_expression(node, assignments=None, seen=None):
    assignments = assignments or {}
    seen = seen or set()
    if isinstance(node, ast.Name) and node.id in assignments and node.id not in seen:
        return _dynamic_sql_expression(assignments[node.id], assignments, seen | {node.id})
    if isinstance(node, (ast.JoinedStr, ast.BinOp)):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    return isinstance(node, ast.BinOp) and (
        _dynamic_sql_expression(node.left, assignments, seen)
        or _dynamic_sql_expression(node.right, assignments, seen)
    )


def _is_secret_assignment(node):
    if isinstance(node, ast.Assign):
        names = [target.id for target in node.targets if isinstance(target, ast.Name)]
        value = _constant_string(node.value)
    elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        names = [node.target.id]
        value = _constant_string(node.value)
    else:
        return False

    if not value or len(value.strip()) < 8:
        return False

    normalized = value.strip().lower()
    if normalized in PLACEHOLDER_VALUES or normalized.startswith("your_"):
        return False

    return any(SECRET_NAME_PATTERN.search(name) for name in names)


class _PythonTaintAnalysis(ast.NodeVisitor):
    """Bounded, intra-module, flow-insensitive-to-branches taint tracking.

    Assignments and aliases are followed in statement order. The analysis never
    executes target code and intentionally avoids claiming interprocedural flow.
    """

    SANITIZERS = {
        "int", "float", "bool", "str", "basename", "quote", "escape",
        "html_escape", "escape_string",
    }
    SQL_SINKS = {"execute", "executemany", "query", "raw"}
    NETWORK_SINKS = {"get", "post", "put", "patch", "delete", "urlopen", "request"}

    def __init__(self, filename, tree=None, call_depth=0):
        self.filename = filename
        self.call_depth = call_depth
        self.functions = {
            node.name: node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        } if tree is not None else {}
        self.taint = {}
        self.sanitized = {}
        self.findings = []
        self.module_aliases = {}
        self.function_aliases = {}

    def _callable_name(self, node):
        name = _qualified_name(node)
        if isinstance(node, ast.Name) and node.id in self.function_aliases:
            return self.function_aliases[node.id]
        parts = name.split(".")
        if parts and parts[0] in self.module_aliases:
            parts[0] = self.module_aliases[parts[0]]
        return ".".join(parts)

    def _source_line(self, node):
        if isinstance(node, ast.Call):
            name = self._callable_name(node.func).lower()
            if name in {"input", "builtins.input"}:
                return node.lineno
            if any(part in name.split(".") for part in {
                "args", "form", "values", "query_params", "headers", "cookies",
            }) and name.endswith(("get", "__getitem__")):
                return node.lineno
            if name in {"request.get_json", "request.json", "request.data", "request.get_data"}:
                return node.lineno
        if isinstance(node, ast.Attribute):
            name = self._callable_name(node).lower()
            if name.endswith((".json", ".data", ".query_params", ".args", ".form", ".values", ".headers", ".cookies")):
                return node.lineno
        if isinstance(node, ast.Subscript):
            name = self._callable_name(node.value).lower()
            if any(part in name.split(".") for part in {
                "args", "form", "values", "query_params", "headers", "cookies",
            }):
                return node.lineno
        return None

    def _taint_sources(self, node, context=None):
        if node is None:
            return set()
        direct = self._source_line(node)
        if direct is not None:
            return {direct}
        if isinstance(node, ast.Name):
            if context and context in self.sanitized.get(node.id, set()):
                return set()
            return set(self.taint.get(node.id, ()))
        if isinstance(node, ast.Call):
            name = self._callable_name(node.func).lower()
            short_name = name.split(".")[-1]
            sanitizer_context = {
                "quote": "command" if name.startswith("shlex.") else None,
                "basename": "path" if name.startswith(("os.path.", "posixpath.", "ntpath.")) else None,
                "escape": "html" if name.startswith(("html.", "markupsafe.")) else None,
            }.get(short_name)
            if short_name in {"int", "float", "bool"} or (context and sanitizer_context == context):
                return set()
        sources = set()
        for child in ast.iter_child_nodes(node):
            sources.update(self._taint_sources(child, context))
        return sources

    def _sanitizer_context(self, node):
        if not isinstance(node, ast.Call):
            return None
        name = self._callable_name(node.func).lower()
        short_name = name.split(".")[-1]
        if short_name == "quote" and name.startswith("shlex."):
            return "command"
        if short_name == "basename" and name.startswith(("os.path.", "posixpath.", "ntpath.")):
            return "path"
        if short_name == "escape" and name.startswith(("html.", "markupsafe.")):
            return "html"
        return None

    def is_sanitized_for(self, node, context):
        if isinstance(node, ast.Name):
            return context in self.sanitized.get(node.id, set())
        return self._sanitizer_context(node) == context

    def _emit(self, rule, cwe, node, sources, description):
        self.findings.append({
            "severity": "HIGH" if rule in {"PYSEC008", "PYSEC010"} else "MEDIUM",
            "confidence": "MEDIUM",
            "test_id": rule,
            "language": "Python",
            "filename": self.filename,
            "line_number": node.lineno,
            "description": description,
            "remediation": remediation_for(rule),
            "cwe": cwe,
            "evidence": {
                "source_lines": sorted(sources),
                "sink_line": node.lineno,
                "analysis": "intra-file AST taint propagation",
            },
        })

    def _target_names(self, target):
        if isinstance(target, ast.Name):
            return [target.id]
        if isinstance(target, (ast.Tuple, ast.List)):
            return [name for child in target.elts for name in self._target_names(child)]
        return []

    def visit_Assign(self, node):
        sources = self._taint_sources(node.value)
        sanitizer_context = self._sanitizer_context(node.value)
        alias_name = _qualified_name(node.value) if isinstance(node.value, (ast.Name, ast.Attribute)) else None
        for target in node.targets:
            for name in self._target_names(target):
                self.taint[name] = set(sources)
                self.sanitized[name] = {sanitizer_context} if sanitizer_context else set()
                if alias_name:
                    self.module_aliases[name] = alias_name
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        sources = self._taint_sources(node.value)
        sanitizer_context = self._sanitizer_context(node.value)
        alias_name = _qualified_name(node.value) if isinstance(node.value, (ast.Name, ast.Attribute)) else None
        for name in self._target_names(node.target):
            self.taint[name] = set(sources)
            self.sanitized[name] = {sanitizer_context} if sanitizer_context else set()
            if alias_name:
                self.module_aliases[name] = alias_name
        self.generic_visit(node)

    def visit_AugAssign(self, node):
        sources = self._taint_sources(node.value) | self._taint_sources(node.target)
        for name in self._target_names(node.target):
            self.taint[name] = set(sources)
        self.generic_visit(node)

    def visit_Call(self, node):
        name = self._callable_name(node.func).lower()
        short_name = name.split(".")[-1]
        command_context = "command" if short_name in {"system", "popen", "run", "call", "check_call", "check_output"} else None
        first_arg_sources = self._taint_sources(node.args[0], "sql") if node.args and short_name in self.SQL_SINKS else set()
        command_sources = self._taint_sources(node.args[0], command_context) if node.args and command_context else set()
        path_sources = self._taint_sources(node.args[0], "path") if node.args and short_name in {"open", "send_file", "send_from_directory"} else set()
        network_sources = self._taint_sources(node.args[0], "network") if node.args and short_name in self.NETWORK_SINKS else set()
        keywords = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}

        if first_arg_sources:
            # DB-API parameter binding supplies query values separately.
            if len(node.args) < 2 and not any(key in keywords for key in {"params", "parameters"}):
                self._emit("PYSEC007", "CWE-89", node, first_arg_sources,
                           "Untrusted data reaches a SQL execution argument without separate parameter binding.")

        if command_sources and (
            name in {"os.system", "os.popen"}
            or (name.startswith("subprocess.") and short_name in {"run", "call", "popen", "check_call", "check_output"}
                and _has_true_keyword(node, "shell"))
        ):
            self._emit("PYSEC008", "CWE-78", node, command_sources,
                       "Untrusted data reaches a shell command execution sink.")

        if path_sources:
            self._emit("PYSEC009", "CWE-22", node, path_sources,
                       "Untrusted data reaches a filesystem path operation; constrain it to an approved directory.")

        if network_sources and short_name in self.NETWORK_SINKS and any(
            token in name for token in {"requests.", "httpx.", "urllib.", "urlopen"}
        ):
            self._emit("PYSEC010", "CWE-918", node, network_sources,
                       "Untrusted data reaches an outbound network request URL; validate scheme, host and resolved address.")

        if self.call_depth < 2 and isinstance(node.func, ast.Name) and node.func.id in self.functions:
            function = self.functions[node.func.id]
            parameters = [*function.args.posonlyargs, *function.args.args]
            child = _PythonTaintAnalysis(self.filename, tree=None, call_depth=self.call_depth + 1)
            child.module_aliases = dict(self.module_aliases)
            child.function_aliases = dict(self.function_aliases)
            for parameter, argument in zip(parameters, node.args):
                child.taint[parameter.arg] = self._taint_sources(argument)
                context = self._sanitizer_context(argument)
                child.sanitized[parameter.arg] = {context} if context else set()
            for parameter, keyword in zip(parameters[len(node.args):], node.keywords):
                if keyword.arg == parameter.arg:
                    child.taint[parameter.arg] = self._taint_sources(keyword.value)
                    context = self._sanitizer_context(keyword.value)
                    child.sanitized[parameter.arg] = {context} if context else set()
            for statement in function.body:
                child.visit(statement)
            self.findings.extend(child.findings)

        self.generic_visit(node)

    def visit_Import(self, node):
        for item in node.names:
            local_name = item.asname or item.name.split(".")[0]
            self.module_aliases[local_name] = item.name

    def visit_ImportFrom(self, node):
        if not node.module:
            return
        for item in node.names:
            local_name = item.asname or item.name
            self.function_aliases[local_name] = f"{node.module}.{item.name}"
            self.module_aliases[local_name] = f"{node.module}.{item.name}"


def _qualified_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _qualified_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def scan_python_file(filename):
    with open(filename, "r", encoding="utf-8-sig") as file:
        source = file.read()
    tree = ast.parse(source, filename=filename)
    module_aliases, function_aliases = _import_aliases(tree)
    assigned_values = {}
    for item in ast.walk(tree):
        if isinstance(item, ast.Assign):
            for target in item.targets:
                if isinstance(target, ast.Name):
                    assigned_values[target.id] = item.value
        elif isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
            assigned_values[item.target.id] = item.value

    findings = []

    taint_analysis = _PythonTaintAnalysis(filename, tree=tree)
    taint_analysis.visit(tree)
    findings.extend(taint_analysis.findings)

    for node in ast.walk(tree):
        if _is_secret_assignment(node):
            findings.append(_finding(
                "MEDIUM",
                "MEDIUM",
                "PYSEC006",
                filename,
                node.lineno,
                "Hardcoded credential-like value detected. Load secrets from a managed secret store or environment configuration.",
            ))

        if not isinstance(node, ast.Call):
            continue

        if isinstance(node.func, ast.Name) and node.func.id == "eval":
            findings.append(_finding(
                "HIGH",
                "HIGH",
                "SEC001",
                filename,
                node.lineno,
                "Use of eval() detected. Avoid dynamic evaluation and parse input with an explicit data format.",
            ))

        subprocess_call = _call_is(node, "subprocess", {"call", "run", "Popen", "check_call", "check_output"}, module_aliases, function_aliases)
        shell_enabled = _has_true_keyword(node, "shell")
        if subprocess_call and shell_enabled and not (
            node.args and taint_analysis.is_sanitized_for(node.args[0], "command")
        ):
            findings.append(_finding(
                "HIGH",
                "HIGH" if shell_enabled else "MEDIUM",
                "SEC002",
                filename,
                node.lineno,
                "subprocess.call() detected. Prefer an argument list and validate command inputs; shell=True requires extra care to avoid shell interpretation.",
            ))

        if (
            _call_is(node, "os", {"system", "popen"}, module_aliases, function_aliases)
            and not (node.args and taint_analysis.is_sanitized_for(node.args[0], "command"))
        ):
            findings.append(_finding(
                "HIGH",
                "HIGH",
                "PYSEC002",
                filename,
                node.lineno,
                "OS command execution detected. Prefer a fixed executable with a validated argument list.",
            ))

        if any(_call_is(node, module, {"load", "loads"}, module_aliases, function_aliases) for module in ("pickle", "dill", "marshal")):
            findings.append(_finding(
                "HIGH",
                "HIGH",
                "PYSEC003",
                filename,
                node.lineno,
                "Unsafe deserialization detected. Do not deserialize untrusted bytes with pickle, dill, or marshal.",
            ))

        yaml_load = _call_is(node, "yaml", {"load", "unsafe_load"}, module_aliases, function_aliases)
        if yaml_load:
            unsafe_loader = False
            for keyword in node.keywords:
                if keyword.arg == "Loader":
                    loader = keyword.value
                    safe_loader = (
                        isinstance(loader, ast.Name) and loader.id == "SafeLoader"
                    ) or (
                        isinstance(loader, ast.Attribute)
                        and loader.attr == "SafeLoader"
                    )
                    unsafe_loader = not safe_loader
            call_name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
            if call_name == "unsafe_load" or unsafe_loader or not any(keyword.arg == "Loader" for keyword in node.keywords):
                findings.append(_finding(
                    "HIGH",
                    "MEDIUM",
                    "PYSEC003",
                    filename,
                    node.lineno,
                    "Unsafe YAML deserialization detected. Use safe_load or an explicitly safe loader for untrusted content.",
                ))

        if isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany"} and node.args:
            if _dynamic_sql_expression(node.args[0], assigned_values):
                findings.append(_finding(
                    "MEDIUM",
                    "MEDIUM",
                    "PYSEC004",
                    filename,
                    node.lineno,
                    "SQL is assembled dynamically before execution. Use parameterized query arguments instead of string interpolation.",
                ))

    return findings
