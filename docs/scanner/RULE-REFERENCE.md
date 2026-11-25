# Scanner rule reference

Scanner `2.0.0`, rule set `2.0.0+a37ba02275`, 45 rules. Generated from `backend/security_engine/scanner/rules.py`.

| ID | Name | Severity | Confidence | CWE | OWASP 2021 | Languages | Technique |
|---|---|---|---|---|---|---|---|
| `SEC001` | Dynamic code evaluation | high | high | CWE-95 | A03:2021 Injection | python | Python AST pattern |
| `SEC002` | Subprocess with shell=True | high | high | CWE-78 | A03:2021 Injection | python | Python AST pattern |
| `PYSEC002` | OS command string execution | high | high | CWE-78 | A03:2021 Injection | python | Python AST pattern |
| `PYSEC003` | Unsafe deserialization | high | high | CWE-502 | A08:2021 Software and Data Integrity Failures | python | Python AST pattern |
| `PYSEC004` | SQL built from string formatting | high | medium | CWE-89 | A03:2021 Injection | python | Python AST pattern |
| `PYSEC006` | Hardcoded credential | high | medium | CWE-798 | A07:2021 Identification and Authentication Failures | python | Python AST pattern |
| `PYSEC007` | Tainted SQL execution | critical | high | CWE-89 | A03:2021 Injection | python | Python AST bounded intra-file taint (with direct-call propagation, depth 2) |
| `PYSEC008` | Tainted shell command | critical | high | CWE-78 | A03:2021 Injection | python | Python AST bounded intra-file taint (with direct-call propagation, depth 2) |
| `PYSEC009` | Tainted file path | high | medium | CWE-22 | A01:2021 Broken Access Control | python | Python AST bounded intra-file taint (with direct-call propagation, depth 2) |
| `PYSEC010` | Server-side request forgery | high | medium | CWE-918 | A10:2021 Server-Side Request Forgery | python | Python AST bounded intra-file taint (with direct-call propagation, depth 2) |
| `JSSEC001` | eval() | high | high | CWE-95 | A03:2021 Injection | javascript, typescript | Lexical match on comment/string-masked source |
| `JSSEC002` | Function constructor | high | high | CWE-94 | A03:2021 Injection | javascript, typescript | Lexical match on comment/string-masked source |
| `JSSEC003` | child_process exec | high | medium | CWE-78 | A03:2021 Injection | javascript, typescript | Lexical match on comment/string-masked source |
| `JSSEC004` | spawn with shell:true | high | high | CWE-78 | A03:2021 Injection | javascript, typescript | Lexical match on comment/string-masked source |
| `JSSEC005` | Hardcoded credential | high | medium | CWE-798 | A07:2021 Identification and Authentication Failures | javascript, typescript | Lexical match on comment/string-masked source |
| `PYSEC011` | Insecure temporary file | medium | high | CWE-377 | A05:2021 Security Misconfiguration | python | Python AST pattern |
| `PYSEC012` | Weak hash algorithm | medium | medium | CWE-328 | A02:2021 Cryptographic Failures | python | Python AST pattern |
| `PYSEC013` | Weak cipher or ECB mode | high | high | CWE-327 | A02:2021 Cryptographic Failures | python | Python AST pattern |
| `PYSEC014` | Insecure randomness for secrets | medium | medium | CWE-338 | A02:2021 Cryptographic Failures | python | Python AST pattern |
| `PYSEC015` | TLS verification disabled | high | high | CWE-295 | A02:2021 Cryptographic Failures | python | Python AST pattern |
| `PYSEC016` | Debug mode enabled | medium | medium | CWE-489 | A05:2021 Security Misconfiguration | python | Python AST pattern |
| `PYSEC017` | Open redirect | medium | medium | CWE-601 | A01:2021 Broken Access Control | python | Python AST pattern |
| `PYSEC018` | Insecure cookie or CSRF configuration | medium | high | CWE-614 | A05:2021 Security Misconfiguration | python | Python AST pattern |
| `PYSEC019` | Cleartext HTTP request | low | medium | CWE-319 | A02:2021 Cryptographic Failures | python | Python AST pattern |
| `PYSEC020` | Sensitive data in logs | medium | medium | CWE-532 | A09:2021 Security Logging and Monitoring Failures | python | Python AST pattern |
| `PYSEC021` | JWT signature verification disabled | high | high | CWE-347 | A07:2021 Identification and Authentication Failures | python | Python AST pattern |
| `PYSEC022` | Overly permissive file mode | medium | high | CWE-732 | A05:2021 Security Misconfiguration | python | Python AST pattern |
| `PYSEC023` | Unfiltered tar extraction | high | medium | CWE-22 | A01:2021 Broken Access Control | python | Python AST pattern |
| `PYSEC024` | XML external entity processing | high | medium | CWE-611 | A05:2021 Security Misconfiguration | python | Python AST pattern |
| `PYSEC025` | Known-format secret in source | critical | high | CWE-798 | A07:2021 Identification and Authentication Failures | python | Python AST pattern |
| `PYSEC026` | Bind to all interfaces | low | low | CWE-1327 | A05:2021 Security Misconfiguration | python | Python AST pattern |
| `JSSEC006` | DOM XSS sink | high | medium | CWE-79 | A03:2021 Injection | javascript, typescript | Lexical match on comment/string-masked source |
| `JSSEC007` | React dangerouslySetInnerHTML | medium | medium | CWE-79 | A03:2021 Injection | javascript, typescript | Lexical match on comment/string-masked source |
| `JSSEC008` | String-based timer evaluation | medium | high | CWE-95 | A03:2021 Injection | javascript, typescript | Lexical match on comment/string-masked source |
| `JSSEC009` | Weak cryptography | medium | high | CWE-327 | A02:2021 Cryptographic Failures | javascript, typescript | Lexical match on comment/string-masked source |
| `JSSEC010` | Insecure randomness for secrets | medium | medium | CWE-338 | A02:2021 Cryptographic Failures | javascript, typescript | Lexical match on comment/string-masked source |
| `JSSEC011` | TLS verification disabled | high | high | CWE-295 | A02:2021 Cryptographic Failures | javascript, typescript | Lexical match on comment/string-masked source |
| `JSSEC012` | Open redirect | medium | medium | CWE-601 | A01:2021 Broken Access Control | javascript, typescript | Lexical match on comment/string-masked source |
| `JSSEC013` | SQL built with interpolation | high | medium | CWE-89 | A03:2021 Injection | javascript, typescript | Lexical match on comment/string-masked source |
| `JSSEC014` | Unsafe deserialization | high | high | CWE-502 | A08:2021 Software and Data Integrity Failures | javascript, typescript | Lexical match on comment/string-masked source |
| `JSSEC015` | Tainted file path | high | medium | CWE-22 | A01:2021 Broken Access Control | javascript, typescript | Lexical match on comment/string-masked source |
| `JSSEC016` | Sensitive data in logs | low | medium | CWE-532 | A09:2021 Security Logging and Monitoring Failures | javascript, typescript | Lexical match on comment/string-masked source |
| `JSSEC017` | Server-side request forgery | high | medium | CWE-918 | A10:2021 Server-Side Request Forgery | javascript, typescript | Lexical match on comment/string-masked source |
| `JSSEC018` | Known-format secret in source | critical | high | CWE-798 | A07:2021 Identification and Authentication Failures | javascript, typescript | Lexical match on comment/string-masked source |
| `JSSEC019` | Node vm code execution | high | medium | CWE-94 | A03:2021 Injection | javascript, typescript | Lexical match on comment/string-masked source |

## Rule details

### SEC001: Dynamic code evaluation

eval()/exec() executes a runtime string as code.

- **Impact:** An attacker controlling the string can run arbitrary Python in the application process.
- **Remediation:** Replace dynamic evaluation with an explicit parser (e.g. json.loads, ast.literal_eval) or a fixed dispatch table.
- **Safer pattern:** `value = ast.literal_eval(text)  # literals only`
- **False-positive considerations:** Evaluation of constant strings is still reported.
- **References:** https://cwe.mitre.org/data/definitions/95.html

### SEC002: Subprocess with shell=True

A subprocess call enables shell interpretation.

- **Impact:** Shell metacharacters in any interpolated value allow command injection.
- **Remediation:** Pass an argument list with shell=False and validate each argument.
- **Safer pattern:** `subprocess.run(["git", "log", ref], check=True)`
- **References:** https://cwe.mitre.org/data/definitions/78.html

### PYSEC002: OS command string execution

os.system/os.popen run a command through the shell.

- **Impact:** Command injection when any part of the string is attacker-influenced.
- **Remediation:** Use subprocess.run with a fixed executable and an argument list.
- **References:** https://cwe.mitre.org/data/definitions/78.html

### PYSEC003: Unsafe deserialization

pickle/dill/marshal or unsafe YAML loaders deserialize data.

- **Impact:** Deserializing attacker data can execute arbitrary code.
- **Remediation:** Use JSON or yaml.safe_load; never unpickle untrusted data.
- **Safer pattern:** `data = yaml.safe_load(stream)`
- **References:** https://cwe.mitre.org/data/definitions/502.html

### PYSEC004: SQL built from string formatting

A SQL statement is composed with f-strings, % or concatenation.

- **Impact:** SQL injection can read or modify any data the database user can access.
- **Remediation:** Use parameter binding (cursor.execute(sql, params)).
- **Safer pattern:** `cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))`
- **False-positive considerations:** Formatting with trusted constants is also reported.
- **References:** https://cwe.mitre.org/data/definitions/89.html

### PYSEC006: Hardcoded credential

A secret-named variable is assigned a literal value.

- **Impact:** Anyone with source access obtains the credential.
- **Remediation:** Load secrets from a secret manager or environment and rotate the exposed value.
- **Safer pattern:** `api_key = os.environ["PAYMENTS_API_KEY"]`
- **False-positive considerations:** Test fixtures with realistic-looking values are reported.
- **References:** https://cwe.mitre.org/data/definitions/798.html

### PYSEC007: Tainted SQL execution

Request-derived data reaches a SQL execute() call without binding.

- **Impact:** Direct SQL injection from user input.
- **Remediation:** Bind values as parameters.
- **References:** https://cwe.mitre.org/data/definitions/89.html

### PYSEC008: Tainted shell command

Request-derived data reaches a shell execution sink.

- **Impact:** Remote command execution.
- **Remediation:** Avoid the shell; use an argument list and an allowlist.
- **References:** https://cwe.mitre.org/data/definitions/78.html

### PYSEC009: Tainted file path

Request-derived data reaches a file path operation.

- **Impact:** Reading or writing files outside the intended directory.
- **Remediation:** Resolve against a fixed base directory and verify containment.
- **Safer pattern:** `path = (BASE / name).resolve(); assert BASE in path.parents`
- **References:** https://cwe.mitre.org/data/definitions/22.html

### PYSEC010: Server-side request forgery

Request-derived data reaches an outbound HTTP request URL.

- **Impact:** Access to internal services and cloud metadata.
- **Remediation:** Allowlist schemes and hosts and block private/link-local addresses after DNS resolution.
- **References:** https://cwe.mitre.org/data/definitions/918.html

### JSSEC001: eval()

eval() executes a runtime string.

- **Impact:** Arbitrary script execution.
- **Remediation:** Use JSON.parse or a dispatch table.
- **References:** https://cwe.mitre.org/data/definitions/95.html

### JSSEC002: Function constructor

new Function() compiles a runtime string.

- **Impact:** Arbitrary script execution.
- **Remediation:** Use predefined functions.
- **References:** https://cwe.mitre.org/data/definitions/94.html

### JSSEC003: child_process exec

exec()/execSync() run a shell command string.

- **Impact:** Command injection.
- **Remediation:** Use execFile/spawn with an argument array.
- **False-positive considerations:** Lexical: RegExp.prototype.exec calls on some expressions can be reported (known false positive); aliased imports (const run = cp.exec) are not detected (known false negative).
- **References:** https://cwe.mitre.org/data/definitions/78.html

### JSSEC004: spawn with shell:true

spawn/execFile enable shell interpretation.

- **Impact:** Command injection.
- **Remediation:** Remove shell:true and pass an argument array.
- **References:** https://cwe.mitre.org/data/definitions/78.html

### JSSEC005: Hardcoded credential

A secret-named property or variable has a literal value.

- **Impact:** Credential disclosure.
- **Remediation:** Load secrets from configuration and rotate the exposed value.
- **References:** https://cwe.mitre.org/data/definitions/798.html

### PYSEC011: Insecure temporary file

tempfile.mktemp() returns a predictable name (race condition).

- **Impact:** Attackers can pre-create or swap the file.
- **Remediation:** Use tempfile.NamedTemporaryFile or mkstemp.
- **Safer pattern:** `with tempfile.NamedTemporaryFile(delete=False) as handle: ...`
- **References:** https://cwe.mitre.org/data/definitions/377.html

### PYSEC012: Weak hash algorithm

MD5 or SHA-1 is used without usedforsecurity=False.

- **Impact:** Collisions and fast brute force undermine integrity and password storage.
- **Remediation:** Use SHA-256 or better; for passwords use Argon2id/scrypt/bcrypt.
- **Safer pattern:** `hashlib.sha256(data).hexdigest()`
- **False-positive considerations:** Non-security checksums should pass usedforsecurity=False.
- **References:** https://cwe.mitre.org/data/definitions/328.html

### PYSEC013: Weak cipher or ECB mode

DES, RC4, Blowfish or ECB mode is used.

- **Impact:** Ciphertext can be decrypted or patterns leak.
- **Remediation:** Use AES-GCM or ChaCha20-Poly1305 (e.g. cryptography's AESGCM).
- **References:** https://cwe.mitre.org/data/definitions/327.html

### PYSEC014: Insecure randomness for secrets

The random module generates a value stored in a token/password/secret-like name.

- **Impact:** Predictable tokens allow account takeover.
- **Remediation:** Use the secrets module (secrets.token_urlsafe).
- **Safer pattern:** `token = secrets.token_urlsafe(32)`
- **References:** https://cwe.mitre.org/data/definitions/338.html

### PYSEC015: TLS verification disabled

Certificate verification is turned off (verify=False, CERT_NONE, unverified context).

- **Impact:** Man-in-the-middle interception of traffic and credentials.
- **Remediation:** Keep verification enabled; supply a CA bundle for private PKI.
- **References:** https://cwe.mitre.org/data/definitions/295.html

### PYSEC016: Debug mode enabled

A web framework runs with debug enabled.

- **Impact:** Interactive debuggers allow code execution and leak internals.
- **Remediation:** Disable debug outside local development; read it from environment.
- **False-positive considerations:** Local-only development entry points are reported.
- **References:** https://cwe.mitre.org/data/definitions/489.html

### PYSEC017: Open redirect

A redirect target comes directly from request parameters.

- **Impact:** Phishing via trusted-domain redirects.
- **Remediation:** Allowlist redirect targets or only accept relative paths.
- **References:** https://cwe.mitre.org/data/definitions/601.html

### PYSEC018: Insecure cookie or CSRF configuration

Secure/HttpOnly cookies or CSRF protection are disabled in configuration.

- **Impact:** Session theft or cross-site request forgery.
- **Remediation:** Set SESSION_COOKIE_SECURE/HTTPONLY=True and keep CSRF protection enabled.
- **References:** https://cwe.mitre.org/data/definitions/614.html

### PYSEC019: Cleartext HTTP request

An outbound request uses a literal http:// URL to a non-local host.

- **Impact:** Traffic can be read or modified in transit.
- **Remediation:** Use https:// endpoints.
- **References:** https://cwe.mitre.org/data/definitions/319.html

### PYSEC020: Sensitive data in logs

A secret-named variable is passed to print() or a logger.

- **Impact:** Secrets persist in log storage readable by more people.
- **Remediation:** Log identifiers, never secrets; redact sensitive fields.
- **References:** https://cwe.mitre.org/data/definitions/532.html

### PYSEC021: JWT signature verification disabled

jwt.decode disables signature verification or allows 'none'.

- **Impact:** Forged tokens are accepted as authentic.
- **Remediation:** Always verify signatures with an explicit algorithm allowlist.
- **References:** https://cwe.mitre.org/data/definitions/347.html

### PYSEC022: Overly permissive file mode

os.chmod grants write/execute to everyone (e.g. 0o777).

- **Impact:** Other local users can modify or replace the file.
- **Remediation:** Use the minimum permission (e.g. 0o600 / 0o640).
- **References:** https://cwe.mitre.org/data/definitions/732.html

### PYSEC023: Unfiltered tar extraction

tarfile extractall() without a safe filter or member validation.

- **Impact:** Archive entries can write outside the target directory.
- **Remediation:** Use extractall(filter='data') (Python 3.12+) or validate each member path.
- **Safer pattern:** `tar.extractall(dest, filter="data")`
- **References:** https://cwe.mitre.org/data/definitions/22.html

### PYSEC024: XML external entity processing

An XML parser is configured to resolve external entities.

- **Impact:** File disclosure and SSRF through XML entities.
- **Remediation:** Use defusedxml, or disable entity resolution.
- **References:** https://cwe.mitre.org/data/definitions/611.html

### PYSEC025: Known-format secret in source

A literal matches a known credential format (AWS, GitHub, Slack, Stripe, private key).

- **Impact:** Direct compromise of the associated account.
- **Remediation:** Revoke and rotate the credential immediately; load it from a secret store.
- **References:** https://cwe.mitre.org/data/definitions/798.html

### PYSEC026: Bind to all interfaces

A server is started on 0.0.0.0.

- **Impact:** Unintended network exposure of development servers.
- **Remediation:** Bind to a specific interface or rely on the deployment platform.
- **False-positive considerations:** Containers commonly bind 0.0.0.0 intentionally.
- **References:** https://cwe.mitre.org/data/definitions/1327.html

### JSSEC006: DOM XSS sink

innerHTML/outerHTML/insertAdjacentHTML/document.write receive a non-literal value.

- **Impact:** Script injection in the user's browser.
- **Remediation:** Use textContent or a vetted sanitizer such as DOMPurify.
- **Safer pattern:** `element.textContent = message;`
- **References:** https://cwe.mitre.org/data/definitions/79.html

### JSSEC007: React dangerouslySetInnerHTML

Raw HTML is injected into a React component.

- **Impact:** Stored or reflected XSS.
- **Remediation:** Render text normally or sanitize with DOMPurify first.
- **References:** https://cwe.mitre.org/data/definitions/79.html

### JSSEC008: String-based timer evaluation

setTimeout/setInterval receive a string, which is evaluated.

- **Impact:** Arbitrary script execution.
- **Remediation:** Pass a function instead of a string.
- **References:** https://cwe.mitre.org/data/definitions/95.html

### JSSEC009: Weak cryptography

MD5/SHA-1 hashing, DES/RC4/ECB ciphers or deprecated createCipher.

- **Impact:** Broken confidentiality or integrity.
- **Remediation:** Use SHA-256+ and AES-256-GCM via createCipheriv.
- **References:** https://cwe.mitre.org/data/definitions/327.html

### JSSEC010: Insecure randomness for secrets

Math.random() is used to generate a token, password or secret.

- **Impact:** Predictable tokens.
- **Remediation:** Use crypto.randomBytes / crypto.getRandomValues / crypto.randomUUID.
- **References:** https://cwe.mitre.org/data/definitions/338.html

### JSSEC011: TLS verification disabled

rejectUnauthorized:false or NODE_TLS_REJECT_UNAUTHORIZED=0.

- **Impact:** Man-in-the-middle attacks.
- **Remediation:** Keep verification on; configure a CA bundle instead.
- **References:** https://cwe.mitre.org/data/definitions/295.html

### JSSEC012: Open redirect

A redirect or location assignment uses request or URL query data.

- **Impact:** Phishing via trusted-domain redirects.
- **Remediation:** Allowlist targets or require relative paths.
- **References:** https://cwe.mitre.org/data/definitions/601.html

### JSSEC013: SQL built with interpolation

A query() call receives a template literal with ${} or string concatenation.

- **Impact:** SQL injection.
- **Remediation:** Use placeholders (query('… WHERE id = $1', [id])).
- **References:** https://cwe.mitre.org/data/definitions/89.html

### JSSEC014: Unsafe deserialization

node-serialize unserialize() or similar evaluates serialized functions.

- **Impact:** Remote code execution.
- **Remediation:** Use JSON.parse on data, never function-capable serializers.
- **References:** https://cwe.mitre.org/data/definitions/502.html

### JSSEC015: Tainted file path

A filesystem call receives req.query/params/body directly.

- **Impact:** Path traversal.
- **Remediation:** Resolve against a base directory and verify containment.
- **References:** https://cwe.mitre.org/data/definitions/22.html

### JSSEC016: Sensitive data in logs

console logging of a password/token/secret identifier.

- **Impact:** Secrets persist in logs.
- **Remediation:** Remove or redact sensitive values before logging.
- **References:** https://cwe.mitre.org/data/definitions/532.html

### JSSEC017: Server-side request forgery

An outbound HTTP call uses req.query/params/body as its URL.

- **Impact:** Access to internal services.
- **Remediation:** Allowlist hosts and block private address ranges.
- **References:** https://cwe.mitre.org/data/definitions/918.html

### JSSEC018: Known-format secret in source

A literal matches a known credential format (AWS, GitHub, Slack, Stripe, private key).

- **Impact:** Direct account compromise.
- **Remediation:** Revoke and rotate immediately; use a secret store.
- **References:** https://cwe.mitre.org/data/definitions/798.html

### JSSEC019: Node vm code execution

vm.runInThisContext/runInNewContext/Script evaluate code strings.

- **Impact:** Arbitrary code execution.
- **Remediation:** Do not evaluate user-influenced code; vm is not a security sandbox.
- **References:** https://cwe.mitre.org/data/definitions/94.html

