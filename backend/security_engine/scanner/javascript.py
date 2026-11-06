import re
from pathlib import Path
from .remediation import cwe_for, remediation_for


JAVASCRIPT_EXTENSIONS = {".js", ".jsx", ".mjs", ".cjs"}
TYPESCRIPT_EXTENSIONS = {".ts", ".tsx"}
SECRET_PATTERN = re.compile(
    r"(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*(?::\s*[A-Za-z_$][\w$<>\[\]| ]*)?\s*[:=]\s*([\"'])([^\"']{8,})\1",
    re.IGNORECASE,
)


def _finding(severity, confidence, test_id, language, filename, line_number, description):
    return {
        "severity": severity,
        "confidence": confidence,
        "test_id": test_id,
        "language": language,
        "filename": filename,
        "line_number": line_number,
        "description": description,
        "remediation": remediation_for(test_id),
        "cwe": cwe_for(test_id),
    }


def _is_comment_only(line):
    stripped = line.strip()
    return not stripped or stripped.startswith(("//", "/*", "*", "*/"))


def _mask_comments_and_strings(source):
    """Keep code punctuation and line breaks while masking literal contents."""
    output = []
    index = 0
    quote = None
    block_comment = False
    line_comment = False
    while index < len(source):
        char = source[index]
        following = source[index + 1] if index + 1 < len(source) else ""
        if char == "\n":
            output.append("\n")
            line_comment = False
            index += 1
            continue
        if line_comment:
            output.append(" ")
            index += 1
            continue
        if block_comment:
            if char == "*" and following == "/":
                output.extend((" ", " "))
                index += 2
                block_comment = False
            else:
                output.append(" ")
                index += 1
            continue
        if quote:
            if char == "\\":
                output.extend((" ", " " if following and following != "\n" else following))
                index += 2 if following else 1
            elif char == quote:
                output.append(" ")
                index += 1
                quote = None
            else:
                output.append(" ")
                index += 1
            continue
        if char == "/" and following == "/":
            output.extend((" ", " "))
            index += 2
            line_comment = True
        elif char == "/" and following == "*":
            output.extend((" ", " "))
            index += 2
            block_comment = True
        elif char in {"'", '"', "`"}:
            output.append(" ")
            quote = char
            index += 1
        else:
            output.append(char)
            index += 1
    return "".join(output)


def _looks_like_real_secret(value):
    normalized = value.strip().lower()
    return normalized not in {
        "changeme",
        "change-me",
        "example-secret",
        "placeholder",
        "replace-me",
        "your-secret",
        "your_password",
    } and not normalized.startswith("your_")


def scan_javascript_file(filename):
    extension = Path(filename).suffix.lower()
    if extension not in JAVASCRIPT_EXTENSIONS | TYPESCRIPT_EXTENSIONS:
        return []

    language = "TypeScript" if extension in TYPESCRIPT_EXTENSIONS else "JavaScript"

    with open(filename, "r", encoding="utf-8") as file:
        source = file.read()
    code = _mask_comments_and_strings(source)
    lines = code.splitlines()
    source_lines = source.splitlines()

    findings = []
    for line_number, line in enumerate(lines, start=1):
        if _is_comment_only(line):
            continue

        secret_match = SECRET_PATTERN.search(source_lines[line_number - 1])
        if (
            secret_match
            and not line[secret_match.start()].isspace()
            and _looks_like_real_secret(secret_match.group(2))
        ):
            findings.append(_finding(
                "MEDIUM",
                "MEDIUM",
                "JSSEC005",
                language,
                filename,
                line_number,
                "Hardcoded credential-like value detected. Load secrets from environment configuration or a managed secret store.",
            ))

    call_rules = (
        (r"\beval\s*\(", "JSSEC001", "HIGH", "Dynamic code execution via eval() detected. Parse data instead of evaluating source text."),
        (r"\b(?:new\s+)?Function\s*\(", "JSSEC002", "HIGH", "Dynamic function construction detected. Avoid compiling executable code from runtime strings."),
        (r"(?:child_process\s*\.\s*)?\b(?:exec|execSync)\s*\(", "JSSEC003", "MEDIUM", "Shell command execution detected. Prefer a fixed executable and validated argument list over exec()."),
    )
    for pattern, rule_id, confidence, description in call_rules:
        for match in re.finditer(pattern, code, flags=re.MULTILINE):
            line_number = code.count("\n", 0, match.start()) + 1
            findings.append(_finding("HIGH", confidence, rule_id, language, filename, line_number, description))

    command_aliases = {
        match.group(1)
        for match in re.finditer(
            r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*child_process\s*\.\s*(?:exec|execSync)\b",
            code,
        )
    }
    for alias in command_aliases:
        if alias in {"exec", "execSync"}:
            continue
        pattern = rf"(?<![\w$.]){re.escape(alias)}\s*\("
        for match in re.finditer(pattern, code):
            line_number = code.count("\n", 0, match.start()) + 1
            findings.append(_finding(
                "HIGH",
                "MEDIUM",
                "JSSEC003",
                language,
                filename,
                line_number,
                "Shell command execution detected through an aliased child_process.exec API. Prefer a fixed executable and validated argument list over exec().",
            ))

    spawn_pattern = re.compile(r"\b(?:spawn|spawnSync)\s*\(")
    for match in spawn_pattern.finditer(code):
        opening = match.end() - 1
        depth = 0
        closing = None
        for index in range(opening, len(code)):
            if code[index] == "(":
                depth += 1
            elif code[index] == ")":
                depth -= 1
                if depth == 0:
                    closing = index
                    break
        if closing is None:
            continue
        arguments = code[opening + 1:closing]
        if re.search(r"\bshell\s*:\s*true\b", arguments):
            line_number = code.count("\n", 0, match.start()) + 1
            findings.append(_finding(
                "HIGH", "HIGH", "JSSEC004", language, filename, line_number,
                "Child-process spawning enables shell interpretation. Avoid shell:true with untrusted or concatenated input.",
            ))

    return findings
