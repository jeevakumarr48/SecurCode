import ast
import re


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
    }


def _constant_string(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _call_is(node, module, attributes):
    return (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == module
        and node.func.attr in attributes
    )


def _has_true_keyword(node, keyword):
    return any(
        item.arg == keyword
        and isinstance(item.value, ast.Constant)
        and item.value.value is True
        for item in node.keywords
    )


def _dynamic_sql_expression(node):
    if isinstance(node, (ast.JoinedStr, ast.BinOp)):
        return True
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format"


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


def scan_python_file(filename):
    with open(filename, "r", encoding="utf-8-sig") as file:
        source = file.read()
    tree = ast.parse(source, filename=filename)

    findings = []

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

        subprocess_call = _call_is(node, "subprocess", {"call", "run", "Popen", "check_call", "check_output"})
        shell_enabled = _has_true_keyword(node, "shell")
        if subprocess_call and shell_enabled:
            findings.append(_finding(
                "HIGH",
                "HIGH" if shell_enabled else "MEDIUM",
                "SEC002",
                filename,
                node.lineno,
                "subprocess.call() detected. Prefer an argument list and validate command inputs; shell=True requires extra care to avoid shell interpretation.",
            ))

        if _call_is(node, "os", {"system", "popen"}):
            findings.append(_finding(
                "HIGH",
                "HIGH",
                "PYSEC002",
                filename,
                node.lineno,
                "OS command execution detected. Prefer a fixed executable with a validated argument list.",
            ))

        if _call_is(node, "pickle", {"load", "loads"}) or _call_is(node, "dill", {"load", "loads"}) or _call_is(node, "marshal", {"load", "loads"}):
            findings.append(_finding(
                "HIGH",
                "HIGH",
                "PYSEC003",
                filename,
                node.lineno,
                "Unsafe deserialization detected. Do not deserialize untrusted bytes with pickle, dill, or marshal.",
            ))

        if _call_is(node, "yaml", {"load", "unsafe_load"}):
            has_loader = any(keyword.arg == "Loader" for keyword in node.keywords)
            if node.func.attr == "unsafe_load" or not has_loader:
                findings.append(_finding(
                    "HIGH",
                    "MEDIUM",
                    "PYSEC003",
                    filename,
                    node.lineno,
                    "Unsafe YAML deserialization detected. Use safe_load or an explicitly safe loader for untrusted content.",
                ))

        if isinstance(node.func, ast.Attribute) and node.func.attr in {"execute", "executemany"} and node.args:
            if _dynamic_sql_expression(node.args[0]):
                findings.append(_finding(
                    "MEDIUM",
                    "MEDIUM",
                    "PYSEC004",
                    filename,
                    node.lineno,
                    "SQL is assembled dynamically before execution. Use parameterized query arguments instead of string interpolation.",
                ))

    return findings
