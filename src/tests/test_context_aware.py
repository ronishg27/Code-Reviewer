"""Test context-aware detection."""

from src.analyzers.security.sql_injection_detector import detect_sql_injection
from src.analyzers.security.command_injection_detector import detect_command_injection


def test_sql_context_aware():
    """Test SQL injection with context tracking."""
    
    print("="*70)
    print("TEST 1: SQL Injection with User Input Tracking")
    print("="*70)
    
    code = '''
def get_user(request):
    # User input is tracked as tainted
    user_id = request.GET['id']
    
    # Taint propagates to query
    query = f"SELECT * FROM users WHERE id = {user_id}"
    
    # VULNERABLE: tainted variable reaches SQL sink
    cursor.execute(query)
'''
    
    issues = list(detect_sql_injection(code, "test.py"))
    
    print(f"\nFound {len(issues)} issues:\n")
    for issue in issues:
        print(f"Line {issue.line}: {issue.severity}")
        print(f"  {issue.message}")
        print()


def test_sql_propagation():
    """Test taint propagation through multiple variables."""
    
    print("="*70)
    print("TEST 2: Taint Propagation Chain")
    print("="*70)
    
    code = '''
def search_products(request):
    # Source: user input
    search_term = request.GET['search']
    
    # Propagation: taint flows to cleaned
    cleaned = search_term.strip()
    
    # Propagation: taint flows to final_term
    final_term = cleaned.lower()
    
    # Sink: tainted data reaches SQL
    query = f"SELECT * FROM products WHERE name LIKE '%{final_term}%'"
    cursor.execute(query)
'''
    
    issues = list(detect_sql_injection(code, "test.py"))
    
    print(f"\nFound {len(issues)} issues:\n")
    for issue in issues:
        print(f"Line {issue.line}: {issue.severity}")
        print(f"  {issue.message}")
        print()


def test_safe_vs_unsafe():
    """Test distinguishing safe from unsafe code."""
    
    print("="*70)
    print("TEST 3: Safe vs Unsafe Comparison")
    print("="*70)
    
    safe_code = '''
def get_user_safe(request):
    user_id = request.GET['id']
    # SAFE: Using parameterized query
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
'''
    
    unsafe_code = '''
def get_user_unsafe(request):
    user_id = request.GET['id']
    # UNSAFE: String concatenation with user input
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
'''
    
    safe_issues = list(detect_sql_injection(safe_code, "safe.py"))
    unsafe_issues = list(detect_sql_injection(unsafe_code, "unsafe.py"))
    
    print(f"Safe code: {len(safe_issues)} issues (should be 0)")
    print(f"Unsafe code: {len(unsafe_issues)} issues (should be 1+)")
    
    if unsafe_issues:
        print(f"\nUnsafe code issue:")
        print(f"  {unsafe_issues[0].message}")
    print()


def test_command_injection_context():
    """Test command injection with context."""
    
    print("="*70)
    print("TEST 4: Command Injection with User Input")
    print("="*70)
    
    code = '''
def process_file(request):
    # User input
    filename = request.args.get('file')
    
    # VULNERABLE: user input in shell command
    os.system(f"cat {filename}")
'''
    
    issues = list(detect_command_injection(code, "test.py"))
    
    print(f"\nFound {len(issues)} issues:\n")
    for issue in issues:
        print(f"Line {issue.line}: {issue.severity}")
        print(f"  {issue.message}")
        print()


def test_function_parameters():
    """Test tracking of function parameters as tainted."""
    
    print("="*70)
    print("TEST 5: Function Parameters as Taint Source")
    print("="*70)
    
    code = '''
def delete_user(user_id):
    # user_id is a function parameter (tainted)
    query = f"DELETE FROM users WHERE id = {user_id}"
    cursor.execute(query)
'''
    
    issues = list(detect_sql_injection(code, "test.py"))
    
    print(f"\nFound {len(issues)} issues:\n")
    for issue in issues:
        print(f"Line {issue.line}: {issue.severity}")
        print(f"  {issue.message}")
        print()


if __name__ == "__main__":
    test_sql_context_aware()
    test_sql_propagation()
    test_safe_vs_unsafe()
    test_command_injection_context()
    test_function_parameters()
    
    print("="*70)
    print("ALL TESTS COMPLETE")
    print("="*70)