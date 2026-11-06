"""Rule-specific guidance grounded in the current scanner rule set."""


REMEDIATION = {
    "SEC001": "Replace dynamic evaluation with an explicit data parser or a fixed dispatch table.",
    "SEC002": "Avoid shell interpretation. Use a fixed executable with an argument list and validate each argument.",
    "PYSEC002": "Avoid OS command strings. Use a fixed executable with validated arguments and least privilege.",
    "PYSEC003": "Do not deserialize untrusted data with pickle, dill, marshal, or unsafe YAML loaders; use a safe data format or safe loader.",
    "PYSEC004": "Bind values with database parameters instead of composing SQL from input or interpolated strings.",
    "PYSEC006": "Remove the hardcoded credential and load a rotated value from a managed secret store or environment configuration.",
    "PYSEC007": "Use parameterized database queries so untrusted values are bound as data, never concatenated into SQL text.",
    "PYSEC008": "Avoid shell interpretation. Use a fixed executable with an argument list; validate arguments and quote only for the specific shell context.",
    "PYSEC009": "Resolve paths against a fixed trusted directory and verify the resolved path remains within that directory before opening it.",
    "PYSEC010": "Validate outbound URL scheme and host against an allowlist, resolve DNS safely, and block loopback, link-local and private addresses.",
    "JSSEC001": "Replace dynamic evaluation with JSON parsing or an explicit, fixed dispatch table.",
    "JSSEC002": "Avoid compiling runtime strings into executable functions; use predefined functions or a data format.",
    "JSSEC003": "Avoid shell command strings. Use a fixed executable and validated argument array.",
    "JSSEC004": "Disable shell mode and pass arguments as an array; validate any user-controlled values.",
    "JSSEC005": "Remove the hardcoded credential and load a rotated value from a managed secret store or environment configuration.",
}

CWE_BY_RULE = {
    "SEC001": "CWE-95",
    "SEC002": "CWE-78",
    "PYSEC002": "CWE-78",
    "PYSEC003": "CWE-502",
    "PYSEC004": "CWE-89",
    "PYSEC006": "CWE-798",
    "PYSEC007": "CWE-89",
    "PYSEC008": "CWE-78",
    "PYSEC009": "CWE-22",
    "PYSEC010": "CWE-918",
    "JSSEC001": "CWE-95",
    "JSSEC002": "CWE-94",
    "JSSEC003": "CWE-78",
    "JSSEC004": "CWE-78",
    "JSSEC005": "CWE-798",
}


def remediation_for(test_id):
    return REMEDIATION.get(test_id, "Review the rule evidence and apply the relevant secure coding guidance.")


def cwe_for(test_id):
    return CWE_BY_RULE.get(test_id)
