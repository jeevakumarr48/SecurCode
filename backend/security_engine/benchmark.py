"""Run a small, explicit regression benchmark for the built-in scanner."""

import argparse
from collections import defaultdict
import json
from pathlib import Path

from security_engine.scanner.engine import scan_file


ROOT = Path(__file__).resolve().parent / "benchmark_fixtures"
CASES = (
    ("Python", "python/vulnerable.py", {"PYSEC004", "PYSEC007", "SEC002", "PYSEC008", "PYSEC010"}),
    ("Python", "python/safe.py", set()),
    ("Python", "python/sanitized.py", set()),
    ("Python", "python/alias_interprocedural.py", {"PYSEC007"}),
    ("Python", "python/interprocedural_command.py", {"PYSEC008", "SEC002"}),
    ("Python", "python/multiline_ssrf.py", {"PYSEC010"}),
    ("JavaScript", "javascript/vulnerable.js", {"JSSEC001", "JSSEC003", "JSSEC005"}),
    ("JavaScript", "javascript/multiline.js", {"JSSEC001"}),
    ("JavaScript", "javascript/interprocedural.js", {"JSSEC001"}),
    ("JavaScript", "javascript/alias.js", {"JSSEC003"}),
    ("JavaScript", "javascript/safe.js", set()),
    ("JavaScript", "javascript/sanitized.js", set()),
)


def _scores(counts):
    tp, fp, fn = counts["tp"], counts["fp"], counts["fn"]
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * precision * recall / (precision + recall)) if precision is not None and recall is not None and precision + recall else 0.0 if precision is not None and recall is not None else None
    return {**counts, "precision": precision, "recall": recall, "f1": f1}


def run_benchmark():
    totals = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    by_language = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    by_rule = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    case_results = []

    for language, relative_path, expected in CASES:
        path = ROOT / relative_path
        predicted = {finding["test_id"] for finding in scan_file(str(path))}
        true_positive = expected & predicted
        false_positive = predicted - expected
        false_negative = expected - predicted
        for bucket in (totals["overall"], by_language[language]):
            bucket["tp"] += len(true_positive)
            bucket["fp"] += len(false_positive)
            bucket["fn"] += len(false_negative)
        for rule in expected | predicted:
            counts = by_rule[rule]
            counts["tp"] += int(rule in true_positive)
            counts["fp"] += int(rule in false_positive)
            counts["fn"] += int(rule in false_negative)
        case_results.append({
            "language": language,
            "fixture": relative_path,
            "expected_rules": sorted(expected),
            "detected_rules": sorted(predicted),
            "true_positives": sorted(true_positive),
            "false_positives": sorted(false_positive),
            "false_negatives": sorted(false_negative),
        })

    return {
        "benchmark": "SecurCode built-in scanner fixture benchmark",
        "scope_note": "Small hand-curated source fixtures, including a JavaScript child_process.exec alias case; not a representative estimate of real-world precision or recall.",
        "fixture_count": len(case_results),
        "overall": _scores(totals["overall"]),
        "by_language": {language: _scores(counts) for language, counts in sorted(by_language.items())},
        "by_rule": {rule: _scores(counts) for rule, counts in sorted(by_rule.items())},
        "cases": case_results,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="Write the JSON result to this path.")
    args = parser.parse_args(argv)
    result = run_benchmark()
    rendered = json.dumps(result, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
