"""Line-level benchmark for the combined v1 scanner.

Each vulnerable fixture line carries ``expect: RULE [RULE…]``. A finding on an
annotated line with a matching rule is a true positive; an expected rule with
no finding is a false negative; any other finding is a false positive.
Safe fixtures contain no expectations, so every finding there is a false
positive. True negatives are counted as expectation-free safe-fixture lines
containing code (an approximation, reported separately).

These fixtures are small and curated; they do not represent real-world
precision or recall.

Usage: python -m security_engine.benchmark_v2 [--json report.json]
"""

from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path

from .scanner.runner import scan_directory

FIXTURES = Path(__file__).resolve().parents[2] / "scanner-fixtures" / "benchmark"
EXPECT = re.compile(r"expect:\s*([A-Z0-9 ]+)")


def _expectations(root: Path) -> dict[tuple[str, int], set[str]]:
    expected: dict[tuple[str, int], set[str]] = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            match = EXPECT.search(line)
            if match:
                expected[(path.relative_to(root).as_posix(), number)] = set(match.group(1).split())
    return expected


def run(root: Path = FIXTURES) -> dict:
    result = scan_directory(str(root))
    expected = _expectations(root)
    found: dict[tuple[str, int], set[str]] = defaultdict(set)
    for finding in result["findings"]:
        found[(finding["file_path"], finding["line"])].add(finding["rule_id"])
    per_rule = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    false_positives, false_negatives = [], []
    for key, rules in found.items():
        for rule in rules:
            if rule in expected.get(key, set()):
                per_rule[rule]["tp"] += 1
            else:
                per_rule[rule]["fp"] += 1
                false_positives.append({"file": key[0], "line": key[1], "rule": rule})
    for key, rules in expected.items():
        for rule in rules - found.get(key, set()):
            per_rule[rule]["fn"] += 1
            false_negatives.append({"file": key[0], "line": key[1], "rule": rule})
    tp = sum(v["tp"] for v in per_rule.values())
    fp = sum(v["fp"] for v in per_rule.values())
    fn = sum(v["fn"] for v in per_rule.values())
    tn = 0
    for path in (root / "safe").rglob("*"):
        if path.is_file():
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                stripped = line.strip()
                if stripped and not stripped.startswith(("#", "//")) and not found.get((path.relative_to(root).as_posix(), number)):
                    tn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {
        "fixtures": sorted({key[0] for key in expected} | {p.relative_to(root).as_posix() for p in (root / "safe").rglob("*") if p.is_file()}),
        "scanner_version": result["scanner_version"],
        "ruleset_version": result["ruleset_version"],
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "true_negatives_safe_lines": tn,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(2 * precision * recall / (precision + recall), 3) if precision + recall else 0.0,
        "per_rule": dict(sorted(per_rule.items())),
        "false_positive_cases": false_positives,
        "false_negative_cases": false_negatives,
        "scan_errors": result["errors"],
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    report = run()
    text = json.dumps(report, indent=2)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8")
    print(json.dumps({k: report[k] for k in ("true_positives", "false_positives", "false_negatives",
                                               "true_negatives_safe_lines", "precision", "recall", "f1")}))
    for case in report["false_positive_cases"]:
        print("FP", case)
    for case in report["false_negative_cases"]:
        print("FN", case)


if __name__ == "__main__":
    main()
