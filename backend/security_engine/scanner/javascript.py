import re
from pathlib import Path


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
    }


def _is_comment_only(line):
    stripped = line.strip()
    return not stripped or stripped.startswith(("//", "/*", "*", "*/"))


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


def scan_javascript_file(filename, strict=False):
    extension = Path(filename).suffix.lower()
    if extension not in JAVASCRIPT_EXTENSIONS | TYPESCRIPT_EXTENSIONS:
        return []

    language = "TypeScript" if extension in TYPESCRIPT_EXTENSIONS else "JavaScript"

    try:
        with open(filename, "r", encoding="utf-8") as file:
            lines = file.readlines()
    except (OSError, UnicodeDecodeError):
        if strict:
            raise
        return []

    findings = []
    for line_number, line in enumerate(lines, start=1):
        if _is_comment_only(line):
            continue

        if re.search(r"\beval\s*\(", line):
            findings.append(_finding(
                "HIGH",
                "HIGH",
                "JSSEC001",
                language,
                filename,
                line_number,
                "Dynamic code execution via eval() detected. Parse data instead of evaluating source text.",
            ))

        if re.search(r"\b(?:new\s+Function|Function)\s*\(", line):
            findings.append(_finding(
                "HIGH",
                "HIGH",
                "JSSEC002",
                language,
                filename,
                line_number,
                "Dynamic function construction detected. Avoid compiling executable code from runtime strings.",
            ))

        if re.search(r"(?:child_process\s*\.\s*)?(?:exec|execSync)\s*\(", line):
            findings.append(_finding(
                "HIGH",
                "MEDIUM",
                "JSSEC003",
                language,
                filename,
                line_number,
                "Shell command execution detected. Prefer a fixed executable and validated argument list over exec().",
            ))

        if re.search(r"\b(?:spawn|spawnSync)\s*\([^)]*\bshell\s*:\s*true", line):
            findings.append(_finding(
                "HIGH",
                "HIGH",
                "JSSEC004",
                language,
                filename,
                line_number,
                "Child-process spawning enables shell interpretation. Avoid shell:true with untrusted or concatenated input.",
            ))

        secret_match = SECRET_PATTERN.search(line)
        if secret_match and _looks_like_real_secret(secret_match.group(2)):
            findings.append(_finding(
                "MEDIUM",
                "MEDIUM",
                "JSSEC005",
                language,
                filename,
                line_number,
                "Hardcoded credential-like value detected. Load secrets from environment configuration or a managed secret store.",
            ))

    return findings
