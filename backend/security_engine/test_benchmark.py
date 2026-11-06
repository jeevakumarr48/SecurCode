from security_engine.benchmark import run_benchmark


def test_curated_scanner_benchmark_matches_vulnerable_and_safe_fixtures():
    result = run_benchmark()

    assert result["fixture_count"] == 12
    assert result["overall"]["tp"] == 15
    assert result["overall"]["fp"] == 0
    assert result["overall"]["fn"] == 0
    assert result["overall"]["precision"] == 1.0
    assert result["overall"]["recall"] == 1.0
    assert result["overall"]["f1"] == 1.0
    assert result["by_language"]["Python"]["tp"] == 9
    assert result["by_language"]["Python"]["fp"] == 0
    assert result["by_language"]["Python"]["fn"] == 0
    assert result["by_language"]["JavaScript"]["tp"] == 6
    assert result["by_language"]["JavaScript"]["fn"] == 0
    alias_case = next(case for case in result["cases"] if case["fixture"] == "javascript/alias.js")
    assert alias_case["true_positives"] == ["JSSEC003"]
    assert alias_case["false_negatives"] == []
