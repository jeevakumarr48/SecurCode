# Scanner architecture, limitations and benchmark

SecurCode's static analysis has two layers that run in the same isolated subprocess (`security_engine/scanner/runner.py`):

1. **Original engine** (`engine.py`, `python.py`, `javascript.py`), 15 rules: Python AST checks with bounded intra-file taint tracking (request-derived sources such as `request.args` flowing into SQL, shell, file and HTTP sinks, with direct-call propagation up to depth 2 and sanitiser recognition), plus JavaScript/TypeScript lexical rules.
2. **Extended rules** (`extended.py`), 30 rules: Python AST pattern rules with import-alias resolution (`PYSEC011`–`PYSEC026`) and JavaScript/TypeScript lexical rules on comment- and string-masked source (`JSSEC006`–`JSSEC019`).

Every rule has registry metadata in `rules.py`: id, name, description, severity, confidence, CWE, OWASP 2021 category, languages, detection technique, remediation, impact, safer example, references and false-positive notes. The full list is in [RULE-REFERENCE.md](RULE-REFERENCE.md).

## Pipeline

```
archive/repo ─► safe extraction ─► file discovery (limits, exclusions, no symlinks)
            ─► original engine + extended rules (per file, exceptions isolated)
            ─► relative paths, registry severity, dedup on (rule, file, line, column)
            ─► policy filters (disabled rules, excluded globs, min severity/confidence)
            ─► context snippet (±2 lines, secrets redacted) + fingerprint
            ─► upsert findings per (project, scope, fingerprint) + per-scan occurrences
            ─► lifecycle reconciliation (new / unchanged / recurring / verified fixed)
```

Exclusions: dependency and build directories (`node_modules`, `venv`, `.venv`, `dist`, `build`, `vendor`, `site-packages`, …), minified or bundled files and source maps, files above the size limit, symbolic links. Binary files are skipped because only `.py`, `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts` and `.tsx` are analysed.

## Fingerprints and their limits

`fingerprint = sha256(rule_id, relative path, whitespace-normalised flagged line, occurrence index among identical lines)`

- ✅ Survives code moving up or down in the file (the demo rescan keeps the MD5 finding's identity when it moves from line 30 to 33).
- ✅ Survives indentation and whitespace changes on the flagged line.
- ❌ A file rename, or an edit to the flagged line itself, produces a new fingerprint. The old finding is then verified fixed and a new one opens.
- ❌ Two identical vulnerable lines in one file are told apart only by order. Reordering them swaps identities.
- Imported SARIF results use the tool's `partialFingerprints` when present.

## Verification semantics

A finding becomes `resolved` / `verified_fixed` only when:

1. a scan of the **same project and scope** (upload default, branch, or PR) **completed without warnings**, and
2. the scan analysed at least one file, and
3. the finding's rule was **enabled** in that scan, and the file was not excluded by policy, and
4. the finding was not reported.

Findings marked `fixed` by a developer but still detected get `verification_status = still_present`. Resolved findings detected again become `reopened` with `recurrence_count + 1`.

## Language support and known limitations

| Language | Technique | Can detect | Cannot detect |
|---|---|---|---|
| Python | AST + bounded intra-file taint (depth 2) + alias-aware pattern rules | Request-derived data reaching SQL, shell, path and HTTP sinks in the same file; dangerous APIs (eval, pickle, unsafe YAML, `verify=False`, weak hashes/ciphers, `mktemp`, `tarfile.extractall`, `jwt.decode` without verification, debug flags, insecure cookie settings, known secret formats) | Cross-file and interprocedural flows beyond depth 2, flows through containers, attributes or class state, framework-specific sources beyond Flask/Django/FastAPI request objects, dynamic imports and `getattr` tricks |
| JavaScript / TypeScript | Lexical rules on source with comments and string contents masked; literal values inspected only where a rule needs them | Direct DOM XSS sinks, `dangerouslySetInnerHTML`, string timers, weak crypto, `Math.random` near secret names, TLS-off flags, direct `req.*` into redirects, fs, `fetch`/axios and SQL template literals, `vm`, `unserialize`, known secret formats | Anything requiring data flow (values passed through variables or functions), aliases (`const run = cp.exec`), JSX expressions split across complex structures, TypeScript type information |
| Others | — | — | Go, Java, C#, Ruby, PHP, dependencies (SCA), IaC, containers (use Trivy, which already runs in CI) |

No interprocedural cross-file analysis exists, and the scanner does not claim it. Results are a subset of what a mature commercial SAST tool would report.

## Benchmark

Two curated, line- or fixture-annotated benchmarks are run in CI.

### Extended rules: line-level (`python -m security_engine.benchmark_v2`)

Fixtures are in `scanner-fixtures/benchmark/` (3 vulnerable and 2 safe files in Python, JS and TSX). Every expected finding is annotated `# expect: RULE` on its line. Any other finding counts as a false positive.

| Metric | Value |
|---|---|
| True positives | 41 |
| False positives | 0 |
| False negatives | 0 |
| Expectation-free code lines in safe fixtures (true-negative proxy) | 45 |
| Precision | 1.000 |
| Recall | 1.000 |
| Rules exercised | 30 (every extended rule) |

The first run found **7 false negatives**. They exposed two real bugs: lookaheads evaluated on masked strings, and Flask's `request` being alias-qualified. Both were fixed before the 41/0/0 result, and the bugs are described in the commit history.

### Original rules: fixture-level (`python -m security_engine.benchmark`)

12 fixtures covering vulnerable, safe and sanitised code, aliases, multi-line calls and interprocedural cases: **TP 15, FP 0, FN 0, precision 1.000, recall 1.000**.

### What these numbers do and do not mean

The fixtures were written alongside the rules, so the scores show the rules behave as designed on known patterns. They do **not** estimate precision or recall on real-world code, which will have false positives (for example secret-named test fixtures) and false negatives (any data flow the rules cannot see). Reports are saved in `backend/reports/scanner-benchmark-v2.json` and `backend/reports/scanner-benchmark.json`.
