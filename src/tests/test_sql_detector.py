# Create a test file: test_sql_detector.py
from src.analyzers.security.sql_injection_detector import detect_sql_injection

test_code = '''
def vulnerable_function(request):
    # Source: user input
    user_id = request.GET['id']
    
    # Propagation
    sanitized_id = user_id.strip()
    
    # Sink: SQL query
    query = f"SELECT * FROM users WHERE id = {sanitized_id}"
    cursor.execute(query)

def also_vulnerable():
    username = input("Enter username: ")
    cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")

def safe_function(request):
    user_id = request.GET['id']
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
'''

print("Testing SQL Injection Detector")
print("=" * 70)

for issue in detect_sql_injection(test_code, "test.py"):
    print(f"\nLine {issue.line}: {issue.severity}")
    print(f"  Message: {issue.message}")
    print(f"  Function: {issue.function}")