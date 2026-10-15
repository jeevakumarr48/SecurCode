
from security_engine.scanner.engine import scan_project

result = scan_project("backend/security_engine/test_target.py")

print("\n=== SECURCODE SCAN RESULTS ===")
print(f"Status: {result['status']}")
print(f"Findings: {result['total_findings']}")

for finding in result["findings"]:
    print("\n--- Finding ---")
    print(f"Severity: {finding['severity']}")
    print(f"Confidence: {finding['confidence']}")
    print(f"Test: {finding['test_id']}")
    print(f"File: {finding['filename']}")
    print(f"Line: {finding['line_number']}")
    print(f"Description: {finding['description']}")
