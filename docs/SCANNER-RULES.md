# Built-in scanner rules

The built-in rules are leads for review. The fixture benchmark in `backend/reports/scanner-benchmark.json` measures only the curated cases named by that suite; its scores are not estimates of real-world detection quality.

Current fixture run: see `backend/reports/scanner-benchmark.json`; rerun `python -m security_engine.benchmark` for current results. Scores apply only to these curated fixtures and are not estimates of real-world detection quality. Counts are rule-presence per fixture, not individual finding counts.

| Rule | Language | Current behavior | CWE |
|---|---|---|---|
| `SEC001` | Python | AST detects calls to `eval` | CWE-95 |
| `SEC002` | Python | AST detects imported subprocess APIs configured with `shell=True`, except recognized shell quoting | CWE-78 |
| `PYSEC002` | Python | AST detects imported `os.system` / `os.popen` calls | CWE-78 |
| `PYSEC003` | Python | AST detects pickle/dill/marshal loads and unsafe YAML loaders | CWE-502 |
| `PYSEC004` | Python | AST detects dynamic SQL expressions, including simple assigned expression aliases | CWE-89 |
| `PYSEC006` | Python | AST detects credential-like literal assignments | CWE-798 |
| `PYSEC007` | Python | Intra-file AST taint tracking detects request/input data reaching SQL execution without separate parameters | CWE-89 |
| `PYSEC008` | Python | Intra-file AST taint tracking detects tainted values reaching shell execution sinks | CWE-78 |
| `PYSEC009` | Python | Intra-file AST taint tracking detects tainted values reaching common file APIs; `basename` is recognized for path context | CWE-22 |
| `PYSEC010` | Python | Intra-file AST taint tracking detects tainted values reaching common HTTP client URL arguments | CWE-918 |
| `JSSEC001` | JavaScript / TypeScript | Lexically detects `eval` calls, including multiline calls | CWE-95 |
| `JSSEC002` | JavaScript / TypeScript | Lexically detects `Function` construction | CWE-94 |
| `JSSEC003` | JavaScript / TypeScript | Lexically detects `exec` / `execSync` calls and direct variable aliases of `child_process.exec` / `execSync` | CWE-78 |
| `JSSEC004` | JavaScript / TypeScript | Lexically detects `spawn` with `shell: true` | CWE-78 |
| `JSSEC005` | JavaScript / TypeScript | Lexically detects credential-like literal assignments | CWE-798 |

Python flow is intra-file, follows simple assignments and import aliases, and expands directly called local function parameters to a maximum depth of two. It is not control-flow sensitive, does not model exception paths, object fields, framework-specific request wrappers, cross-module calls, general return summaries, or arbitrary validation logic. The sanitizer allowlist is contextual and deliberately small. Unsupported constructs are not proof of safety.

JavaScript and TypeScript still use a lexical pass, not an AST parser or taint engine. They do not support semantic source-to-sink analysis for SQL injection, XSS, SSRF, path traversal, redirects, DOM APIs, imported/destructured aliases, or framework-specific behavior. The Python and JavaScript labels indicate file routing, not equal analysis depth.
