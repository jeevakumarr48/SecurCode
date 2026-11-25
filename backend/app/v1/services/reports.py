"""Exports (CSV, JSON, SARIF 2.1.0) and printable HTML security reports."""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
from collections import Counter
from functools import lru_cache
from pathlib import Path

import jsonschema

from security_engine.scanner.rules import RULES, SCANNER_VERSION, ruleset_version

from ..db import utcnow

SCHEMA_PATH = Path(__file__).with_name("sarif-schema-2.1.0.json")
SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0", "info": "0.0"}
CSV_FIELDS = ["id", "project", "rule_id", "title", "severity", "confidence", "status", "verification_status", "cwe", "owasp",
              "file_path", "line", "assignee", "due_date", "first_detected_at", "last_detected_at", "labels"]
LIMITATIONS = [
    "Results reflect only the enabled SecurCode rules (Python AST rules, bounded intra-file taint analysis, and lexical "
    "JavaScript/TypeScript rules). Absence of findings is not proof of security.",
    "No interprocedural cross-file data-flow, dependency (SCA) or runtime (DAST) analysis is included.",
    "Findings are tracked by content fingerprints; renamed files or edits to a flagged line can appear as new findings.",
    "The posture score is an internal prioritisation signal, not a certification.",
]


@lru_cache(maxsize=1)
def _validator():
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return jsonschema.Draft4Validator(schema)


def validate_sarif(document: dict) -> list[str]:
    errors = sorted(_validator().iter_errors(document), key=lambda e: list(e.absolute_path))
    return [f"{'/'.join(str(p) for p in e.absolute_path) or '(root)'}: {e.message[:200]}" for e in errors[:20]]


def _csv_safe(value) -> str:
    """Neutralise spreadsheet formula injection (CWE-1236)."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in {"=", "+", "-", "@", "\t", "\r"} else text


def findings_csv(rows: list[dict]) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({key: _csv_safe(",".join(row[key]) if isinstance(row.get(key), list) else row.get(key)) for key in CSV_FIELDS})
    return buffer.getvalue()


def findings_sarif(rows: list[dict], scan_meta: dict | None = None) -> dict:
    rule_ids = sorted({row["rule_id"] for row in rows})
    rule_index = {rule_id: index for index, rule_id in enumerate(rule_ids)}
    driver_rules = []
    for rule_id in rule_ids:
        rule = RULES.get(rule_id)
        entry = {"id": rule_id, "name": (rule.name if rule else rule_id).replace(" ", ""),
                 "shortDescription": {"text": rule.name if rule else rule_id},
                 "fullDescription": {"text": rule.description if rule else rule_id},
                 "help": {"text": rule.remediation if rule else "See finding guidance."},
                 "properties": {"tags": ["security"] + ([rule.cwe] if rule and rule.cwe else []),
                                "security-severity": SECURITY_SEVERITY.get(rule.severity if rule else "medium", "5.5")}}
        if rule and rule.references:
            entry["helpUri"] = rule.references[0]
        driver_rules.append(entry)
    results = []
    for row in rows:
        result = {
            "ruleId": row["rule_id"],
            "ruleIndex": rule_index[row["rule_id"]],
            "level": SARIF_LEVEL.get(row["severity"], "warning"),
            "message": {"text": row.get("title") or row["rule_id"]},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": row["file_path"], "uriBaseId": "SRCROOT"},
                                                **({"region": {"startLine": int(row["line"])}} if row.get("line") else {})}}],
            "partialFingerprints": {"securcodeFingerprint/v1": row["fingerprint"]},
            "properties": {"severity": row["severity"], "confidence": row["confidence"], "status": row["status"],
                           "securcodeFindingId": row["id"]},
        }
        if row["status"] in {"false_positive", "accepted_risk"}:
            result["suppressions"] = [{"kind": "external", "status": "accepted",
                                       "justification": row["status"].replace("_", " ")}]
        results.append(result)
    run = {
        "tool": {"driver": {"name": "SecurCode", "version": SCANNER_VERSION, "semanticVersion": SCANNER_VERSION,
                            "informationUri": "https://github.com/jeevakumarr48/SecurCode", "rules": driver_rules}},
        "results": results,
        "originalUriBaseIds": {"SRCROOT": {"description": {"text": "Repository root"}}},
        "properties": {"rulesetVersion": ruleset_version(), "generatedAt": utcnow().isoformat(), **(scan_meta or {})},
    }
    if scan_meta and scan_meta.get("commit_sha"):
        run["versionControlProvenance"] = [{"repositoryUri": scan_meta.get("repository_url") or "https://github.com/unknown/unknown",
                                            "revisionId": scan_meta["commit_sha"],
                                            **({"branch": scan_meta["branch"]} if scan_meta.get("branch") else {})}]
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": [run]}


def parse_sarif_results(document: dict) -> list[dict]:
    """Normalise a validated SARIF log into SecurCode raw findings."""
    findings = []
    for run in document.get("runs", []):
        driver = run.get("tool", {}).get("driver", {})
        tool = str(driver.get("name", "external"))[:40]
        rules = {r.get("id"): r for r in driver.get("rules", []) if isinstance(r, dict)}
        for result in run.get("results", [])[:20000]:
            rule_id = str(result.get("ruleId") or (result.get("rule") or {}).get("id") or "external")[:40]
            location = ((result.get("locations") or [{}])[0] or {}).get("physicalLocation", {})
            uri = str(location.get("artifactLocation", {}).get("uri", "unknown"))
            if uri.startswith("file://"):
                uri = uri[7:]
            uri = uri.lstrip("/").replace("\\", "/")
            if ".." in uri.split("/"):
                continue
            region = location.get("region", {}) or {}
            level = result.get("level") or rules.get(rule_id, {}).get("defaultConfiguration", {}).get("level", "warning")
            security = (result.get("properties") or {}).get("security-severity") or \
                (rules.get(rule_id, {}).get("properties") or {}).get("security-severity")
            try:
                score = float(security) if security is not None else None
            except (TypeError, ValueError):
                score = None
            if score is not None:
                severity = "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
            else:
                severity = {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(level, "medium")
            message = (result.get("message") or {}).get("text") or rules.get(rule_id, {}).get("shortDescription", {}).get("text") or rule_id
            fingerprints = result.get("partialFingerprints") or result.get("fingerprints") or {}
            stable = next(iter(fingerprints.values()), None) if fingerprints else None
            snippet = ((region.get("snippet") or {}).get("text") or "")[:400]
            findings.append({
                "rule_id": rule_id if rule_id in RULES else f"{tool}:{rule_id}"[:40], "severity": severity, "confidence": "medium",
                "file_path": uri[:1000], "line": region.get("startLine"), "description": str(message)[:2000],
                "external_fingerprint": stable, "snippet": snippet, "tool": tool, "title": str(message)[:200],
            })
    return findings


def external_fingerprint(item: dict) -> str:
    material = item.get("external_fingerprint") or f"{item['rule_id']}|{item['file_path']}|{item.get('snippet') or item.get('line')}"
    return hashlib.sha256(f"sarif\x1f{material}".encode()).hexdigest()


# --- Printable HTML report ---------------------------------------------------------

def _esc(value) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def render_html_report(title: str, scope: dict, summary: dict, findings: list[dict], sections: list[tuple[str, str]] | None = None) -> str:
    severity = Counter(f["severity"] for f in findings)
    rows = "".join(
        f"<tr><td class='sev {_esc(f['severity'])}'>{_esc(f['severity'])}</td><td>{_esc(f['title'])}<div class='muted'>{_esc(f['rule_id'])}"
        f"{' · ' + _esc(f['cwe']) if f.get('cwe') else ''}</div></td><td><code>{_esc(f['file_path'])}:{_esc(f.get('line') or '')}</code></td>"
        f"<td>{_esc(f['status'])}</td><td>{_esc(f.get('assignee') or '—')}</td></tr>"
        for f in findings[:2000]
    )
    remediation = "".join(
        f"<li><strong>{_esc(rule_id)} — {_esc(RULES[rule_id].name)}</strong>: {_esc(RULES[rule_id].remediation)}</li>"
        for rule_id in sorted({f["rule_id"] for f in findings if f["rule_id"] in RULES})
    )
    scope_rows = "".join(f"<tr><th>{_esc(k)}</th><td>{_esc(v)}</td></tr>" for k, v in scope.items())
    summary_rows = "".join(f"<div class='stat'><span>{_esc(v)}</span>{_esc(k)}</div>" for k, v in summary.items())
    extra = "".join(f"<h2>{_esc(heading)}</h2>{body}" for heading, body in (sections or []))
    dist = "".join(f"<div class='stat'><span>{severity.get(s, 0)}</span>{s}</div>" for s in ("critical", "high", "medium", "low", "info"))
    limitations = "".join(f"<li>{_esc(item)}</li>" for item in LIMITATIONS)
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>{_esc(title)}</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
body{{font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;color:#1d2433;margin:32px auto;max-width:1040px;padding:0 24px}}
h1{{font-size:24px;margin:0 0 4px}}h2{{font-size:17px;margin:28px 0 10px;border-bottom:1px solid #dde3ee;padding-bottom:6px}}
.muted{{color:#5f6b7f;font-size:12px}}table{{width:100%;border-collapse:collapse}}td,th{{text-align:left;padding:6px 8px;border-bottom:1px solid #eef1f6;vertical-align:top}}
th{{width:220px;color:#5f6b7f;font-weight:600}}.stats{{display:flex;gap:12px;flex-wrap:wrap}}.stat{{border:1px solid #dde3ee;border-radius:8px;padding:8px 14px;min-width:90px;color:#5f6b7f;font-size:12px}}
.stat span{{display:block;font-size:20px;font-weight:700;color:#1d2433}}.sev{{font-weight:700;text-transform:capitalize}}.critical{{color:#a50e0e}}.high{{color:#c2410c}}.medium{{color:#a16207}}.low{{color:#1d4ed8}}
code{{font-size:12px;word-break:break-all}}@media print{{body{{margin:0}}a{{color:inherit}}}}
</style></head><body>
<h1>{_esc(title)}</h1><div class="muted">Generated {utcnow().strftime('%Y-%m-%d %H:%M UTC')} by SecurCode {SCANNER_VERSION} · rule set {ruleset_version()}</div>
<h2>Scope</h2><table>{scope_rows}</table>
<h2>Summary</h2><div class="stats">{summary_rows}</div>
<h2>Severity distribution</h2><div class="stats">{dist}</div>
{extra}
<h2>Findings ({len(findings)})</h2><table><thead><tr><th style="width:80px">Severity</th><th>Finding</th><th>Location</th><th>Status</th><th>Assignee</th></tr></thead><tbody>{rows or "<tr><td colspan=5>No findings in scope.</td></tr>"}</tbody></table>
<h2>Remediation recommendations</h2><ul>{remediation or "<li>No rule-specific recommendations.</li>"}</ul>
<h2>Limitations</h2><ul>{limitations}</ul>
</body></html>"""
