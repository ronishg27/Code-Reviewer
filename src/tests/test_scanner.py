# test_scanner.py
"""Test the SecurityScanner to ensure it works correctly."""

from src.scanner import SecurityScanner, scan_code

def test_basic_scan():
    """Test basic scanning functionality."""
    code = '''
import os

def vulnerable_function(user_input):
    # Command injection
    os.system(f"ls {user_input}")
    
    # SQL injection
    cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")
    
    # Hardcoded secret
    API_KEY = "sk-1234567890abcdef1234567890abcdef"
    
    # Bare except
    try:
        risky_operation()
    except:
        pass
'''
    
    result = scan_code(code, "test.py")
    
    print(f"\n✅ Scan completed!")
    print(f"Total issues: {result.total_issues}")
    print(f"Has critical: {result.has_critical}")
    print(f"Has high: {result.has_high}")
    
    # Should find at least:
    # - 1 command injection (CRITICAL)
    # - 1 SQL injection (CRITICAL)
    # - 1 hardcoded secret (CRITICAL)
    # - 1 bare except (CRITICAL)
    assert result.total_issues >= 4, f"Expected >= 4 issues, got {result.total_issues}"
    
    print("\n✅ All assertions passed!")
    
    # Print detailed report
    result.print_report(verbose=True, show_metrics=True)


def test_metrics():
    """Test metrics calculation."""
    code = '''
def complex_function(a, b, c, d, e, f):
    # Complexity: 11 (1 base + 10 if statements)
    if a > 0:
        if b > 0:
            if c > 0:
                if d > 0:
                    if e > 0:
                        if f > 0:
                            if a < b:
                                if b < c:
                                    if c < d:
                                        if d < e:
                                            return f
    return 0
'''
    
    result = scan_code(code, "metrics_test.py")
    
    print(f"\n✅ Metrics calculated!")
    summary = result.get_metrics_summary()
    
    print(f"Functions: {summary['num_functions']}")
    print(f"Avg Complexity: {summary['avg_complexity']:.1f}")
    print(f"High complexity: {summary['high_complexity_count']}")
    
    assert summary['num_functions'] == 1
    # With complexity > 10, should flag as high
    assert summary['avg_complexity'] > 10, f"Expected complexity > 10, got {summary['avg_complexity']}"
    
    print("✅ Metrics test passed!")


def test_severity_grouping():
    """Test issue grouping by severity."""
    code = '''
import os

def vulnerable_function(user_input):
    # CRITICAL issues
    API_KEY = "sk-1234567890abcdef1234567890abcdef"
    os.system(f"rm -rf {user_input}")
    eval(user_input)

# HIGH issues
def function_with_many_params(a, b, c, d, e, f, g, h):
    pass

# MEDIUM issues
def moderately_nested():
    if True:
        if True:
            if True:
                if True:
                    pass
'''
    
    result = scan_code(code, "severity_test.py")
    by_sev = result.by_severity()
    
    print(f"\n✅ Severity grouping:")
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = len(by_sev[sev])
        if count > 0:
            print(f"  {sev}: {count}")
    
    # Should have at least 2 critical (hardcoded secret, command injection, eval)
    assert len(by_sev['CRITICAL']) >= 2, f"Expected >= 2 critical, got {len(by_sev['CRITICAL'])}"
    print("✅ Severity test passed!")


def test_json_export():
    """Test JSON export."""
    code = '''
def test_func(user_input):
    os.system(f"ls {user_input}")
'''
    result = scan_code(code, "json_test.py")
    
    json_str = result.to_json()
    
    import json
    data = json.loads(json_str)
    
    assert 'file_path' in data
    assert 'total_issues' in data
    assert 'issues' in data
    assert 'metrics' in data
    assert 'summary' in data
    
    print("\n✅ JSON export works!")
    print(json_str[:200] + "...")


def test_empty_code():
    """Test scanning empty code."""
    result = scan_code("", "empty.py")
    
    # Empty code should have no issues or just a parsing error
    assert result.total_issues <= 1
    assert result.get_metrics_summary()['num_functions'] == 0
    
    print("\n✅ Empty code handled!")


def test_syntax_error():
    """Test handling of syntax errors."""
    bad_code = '''
def broken(
    invalid syntax here
'''
    
    result = scan_code(bad_code, "broken.py")
    
    # Should have at least one error issue
    by_sev = result.by_severity()
    
    print(f"\n✅ Syntax error handled!")
    print(f"Error issues: {len(by_sev.get('ERROR', []))}")
    assert len(by_sev.get('ERROR', [])) >= 1


def test_deduplication():
    """Test that duplicate issues are removed."""
    # This shouldn't happen with good detectors, but test the safety net
    code = '''
def test():
    pass
'''
    
    scanner = SecurityScanner()
    result = scanner.scan(code, "dedup_test.py")
    
    # Count issues by line+message
    issue_keys = [(i.line, i.message) for i in result.issues]
    unique_keys = set(issue_keys)
    
    assert len(issue_keys) == len(unique_keys), "Duplicate issues detected!"
    print("\n✅ Deduplication works!")


if __name__ == "__main__":
    print("="*70)
    print("SCANNER VALIDATION TESTS")
    print("="*70)
    
    tests = [
        ("Basic Scan", test_basic_scan),
        ("Metrics", test_metrics),
        ("Severity Grouping", test_severity_grouping),
        ("JSON Export", test_json_export),
        ("Empty Code", test_empty_code),
        ("Syntax Error", test_syntax_error),
        ("Deduplication", test_deduplication),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            print(f"\n{'='*70}")
            print(f"Running: {name}")
            print(f"{'='*70}")
            test_func()
            passed += 1
            print(f"\n✅ {name} PASSED")
        except AssertionError as e:
            failed += 1
            print(f"\n❌ {name} FAILED: {str(e)}")
        except Exception as e:
            failed += 1
            print(f"\n❌ {name} ERROR: {str(e)}")
            import traceback
            traceback.print_exc()
    
    print(f"\n{'='*70}")
    print(f"RESULTS: {passed} passed, {failed} failed")
    print(f"{'='*70}")
    
    if failed == 0:
        print("\n🎉 ALL TESTS PASSED!")
    else:
        print(f"\n⚠️  {failed} tests failed. Review and fix before proceeding.")