import ast
import re
from typing import Dict, Generator, Set, List, Optional, Tuple
from dataclasses import dataclass

from src.analyzers.security.base import BaseDetector, Rule, Severity, run_detector
from src.models import make_issue, Issue


class AssertDetector(BaseDetector):
    """
    Detector for problematic assert statement usage.
    
    Assert statements are removed when Python runs with optimization (-O flag),
    making them unsuitable for:
    - Security checks (authentication, authorization)
    - Input validation
    - Data validation
    - Error handling in production code
    """
    
    DETECTOR_NAME = "Assert Usage Detector"
    DETECTOR_RULE = "Problematic Assert Usage"
    
    # Keywords in assert messages or test expressions that suggest security checks
    SECURITY_KEYWORDS: Set[str] = {
        'auth', 'authenticate', 'authenticated', 'authentication',
        'authorize', 'authorized', 'authorization',
        'permission', 'permissions', 'permitted',
        'access', 'allowed', 'denied',
        'admin', 'administrator', 'superuser', 'root',
        'role', 'roles', 'privilege', 'privileges',
        'login', 'logged_in', 'logged_out',
        'session', 'token', 'jwt', 'oauth',
        'credentials', 'password', 'secret',
        'secure', 'security', 'sanitize', 'sanitized',
        'verified', 'verify', 'verification',
        'valid_user', 'is_user', 'is_admin',
        'can_access', 'has_access', 'check_access',
        'can_edit', 'can_delete', 'can_create', 'can_view',
    }
    
    # Keywords that suggest input/data validation
    VALIDATION_KEYWORDS: Set[str] = {
        'valid', 'validate', 'validated', 'validation',
        'invalid', 'check', 'verify', 'verified',
        'sanitize', 'sanitized', 'clean', 'cleaned',
        'input', 'user_input', 'form', 'request',
        'data', 'param', 'parameter', 'argument',
        'required', 'mandatory', 'optional',
        'empty', 'not_empty', 'nonempty',
        'length', 'size', 'count',
        'range', 'bounds', 'limit',
        'format', 'pattern', 'regex',
        'type', 'isinstance', 'issubclass',
        'email', 'phone', 'url', 'path',
        'positive', 'negative', 'nonzero',
        'exists', 'not_none', 'notnull',
    }
    
    # Keywords that suggest type checking
    TYPE_CHECK_KEYWORDS: Set[str] = {
        'isinstance', 'issubclass', 'type',
        'str', 'int', 'float', 'bool', 'list', 'dict', 'tuple', 'set',
        'bytes', 'bytearray', 'memoryview',
        'callable', 'iterable', 'iterator',
    }
    
    # Patterns for test file detection
    TEST_FILE_PATTERNS: List[str] = [
        r'test_.*\.py$',
        r'.*_test\.py$',
        r'tests?/.*\.py$',
        r'testing/.*\.py$',
        r'conftest\.py$',
        r'.*tests\.py$',
    ]
    
    # Patterns for test function/class detection
    TEST_CONTEXT_PATTERNS: List[str] = [
        r'^test_',
        r'_test$',
        r'^Test[A-Z]',
        r'TestCase$',
    ]
    
    # Function names where asserts are acceptable
    ALLOWED_CONTEXTS: Set[str] = {
        'test', 'debug', 'assert_', '_assert',
        'check_invariant', 'invariant', 'precondition', 'postcondition',
    }
    
    def __init__(self, file_path: str = "UNKNOWN", check_tests: bool = False):
        super().__init__(file_path)
        self.check_tests = check_tests
        self.is_test_file = self._is_test_file()
        self.assert_count = 0
    
    def _is_test_file(self) -> bool:
        """Check if the current file is a test file."""
        for pattern in self.TEST_FILE_PATTERNS:
            if re.search(pattern, self.file_path, re.IGNORECASE):
                return True
        return False
    
    def _is_test_context(self) -> bool:
        """Check if current context is a test function/class."""
        if self.current_function:
            for pattern in self.TEST_CONTEXT_PATTERNS:
                if re.match(pattern, self.current_function, re.IGNORECASE):
                    return True
        
        if self.current_class:
            for pattern in self.TEST_CONTEXT_PATTERNS:
                if re.match(pattern, self.current_class, re.IGNORECASE):
                    return True
        
        return False
    
    def _is_allowed_context(self) -> bool:
        """Check if assert is in an allowed context."""
        if self.current_function:
            func_lower = self.current_function.lower()
            for allowed in self.ALLOWED_CONTEXTS:
                if allowed in func_lower:
                    return True
        return False
    
    def visit_Assert(self, node: ast.Assert) -> None:
        """Analyze assert statements for problematic usage."""
        self.assert_count += 1
        
        # Skip test files unless explicitly checking them
        if self.is_test_file and not self.check_tests:
            self.generic_visit(node)
            return
        
        # Skip test contexts
        if self._is_test_context() and not self.check_tests:
            self.generic_visit(node)
            return
        
        # Skip explicitly allowed contexts
        if self._is_allowed_context():
            self.generic_visit(node)
            return
        
        # Analyze the assert
        issues = self._analyze_assert(node)
        
        for severity, message, recommendation in issues:
            rule = Rule(
                severity=severity,
                message=message,
                recommendation=recommendation
            )
            self.report_issue(node, rule, "assert")
        
        self.generic_visit(node)
    
    def _analyze_assert(self, node: ast.Assert) -> List[Tuple[Severity, str, str]]:
        """Analyze an assert statement and return list of issues."""
        issues = []
        
        # Extract text from the assert for analysis
        test_text = self._extract_text(node.test)
        msg_text = self._extract_text(node.msg) if node.msg else ""
        combined_text = f"{test_text} {msg_text}".lower()
        
        # Check for security-related asserts
        security_match = self._find_keyword_match(combined_text, self.SECURITY_KEYWORDS)
        if security_match:
            issues.append((
                Severity.CRITICAL,
                f"Assert used for security check ('{security_match}'){self.get_context_string()}. "
                f"Assert statements are removed with -O flag.",
                "Replace with proper security checks using if statements and raise exceptions "
                "(e.g., PermissionError, AuthenticationError) or use a security framework."
            ))
        
        # Check for validation-related asserts
        validation_match = self._find_keyword_match(combined_text, self.VALIDATION_KEYWORDS)
        if validation_match and not security_match:  # Avoid duplicate reports
            issues.append((
                Severity.HIGH,
                f"Assert used for data/input validation ('{validation_match}'){self.get_context_string()}. "
                f"Assert statements are removed with -O flag.",
                "Replace with proper validation using if statements and raise ValueError, "
                "TypeError, or custom validation exceptions."
            ))
        
        # Check for type checking
        if self._is_type_check(node.test):
            issues.append((
                Severity.MEDIUM,
                f"Assert used for type checking{self.get_context_string()}. "
                f"Assert statements are removed with -O flag.",
                "Use proper type checking with isinstance() and raise TypeError, "
                "or use type hints with runtime checking (e.g., pydantic, typeguard)."
            ))
        
        # Check for comparison with None
        if self._is_none_check(node.test):
            issues.append((
                Severity.MEDIUM,
                f"Assert used for None check{self.get_context_string()}. "
                f"Assert statements are removed with -O flag.",
                "Use 'if x is None: raise ValueError()' for required value checks."
            ))
        
        # Check for boolean condition checks (generic)
        if not issues and self._is_production_context():
            issues.append((
                Severity.LOW,
                f"Assert statement in production code{self.get_context_string()}. "
                f"Assert statements are removed with -O flag.",
                "Consider replacing with explicit validation or remove if used only for debugging."
            ))
        
        return issues
    
    def _extract_text(self, node: ast.AST) -> str:
        """Extract readable text from an AST node for analysis."""
        texts = []
        
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                texts.append(child.id)
            elif isinstance(child, ast.Attribute):
                texts.append(child.attr)
            elif isinstance(child, ast.Constant) and isinstance(child.value, str):
                texts.append(child.value)
            elif isinstance(child, ast.Call):
                if isinstance(child.func, ast.Name):
                    texts.append(child.func.id)
                elif isinstance(child.func, ast.Attribute):
                    texts.append(child.func.attr)
        
        return ' '.join(texts)
    
    def _find_keyword_match(self, text: str, keywords: Set[str]) -> Optional[str]:
        """Find if any keyword matches in the text."""
        text_lower = text.lower()
        for keyword in keywords:
            # Match whole words or underscored parts
            pattern = rf'\b{re.escape(keyword)}\b|_{keyword}|{keyword}_'
            if re.search(pattern, text_lower):
                return keyword
        return None
    
    def _is_type_check(self, test: ast.AST) -> bool:
        """Check if the assert is a type check."""
        if isinstance(test, ast.Call):
            if isinstance(test.func, ast.Name):
                return test.func.id in {'isinstance', 'issubclass', 'callable'}
        
        # Check for type() comparison
        if isinstance(test, ast.Compare):
            for comparator in [test.left] + test.comparators:
                if isinstance(comparator, ast.Call):
                    if isinstance(comparator.func, ast.Name) and comparator.func.id == 'type':
                        return True
        
        return False
    
    def _is_none_check(self, test: ast.AST) -> bool:
        """Check if the assert is a None check."""
        # assert x is not None
        if isinstance(test, ast.Compare):
            if any(isinstance(op, (ast.Is, ast.IsNot)) for op in test.ops):
                for comparator in test.comparators:
                    if isinstance(comparator, ast.Constant) and comparator.value is None:
                        return True
        
        # assert x (where x could be None)
        if isinstance(test, ast.Name):
            return True
        
        return False
    
    def _is_production_context(self) -> bool:
        """Check if the current context appears to be production code."""
        # Not a test file and not a test function
        if self.is_test_file:
            return False
        
        if self._is_test_context():
            return False
        
        # Check for debug-related function names
        if self.current_function:
            func_lower = self.current_function.lower()
            debug_indicators = {'debug', 'test', 'mock', 'stub', 'fake'}
            if any(indicator in func_lower for indicator in debug_indicators):
                return False
        
        return True
    
    def _on_call(self, node: ast.Call, func_name: str, resolved_name: str) -> None:
        """Not used for assert detection but required by base class."""
        pass


def detect_assert_usage(
    code: str,
    file_path: str = "UNKNOWN",
    check_tests: bool = False
):
#  -> List[Issue]:
    """
    Detect problematic assert usage in code.
    
    Args:
        code: The source code to analyze
        file_path: The path of the file being analyzed
        check_tests: Whether to check test files (default: False)
        
    Yields:
        Issue objects for each problematic assert
    """
    yield from run_detector(
        lambda fp: AssertDetector(fp, check_tests),
        code,
        file_path
    )


# Updated run_detector to support factory functions
def run_detector_with_options(
    detector_factory,
    code: str,
    file_path: str = "UNKNOWN"
):
    """Run a detector created by a factory function."""
    try:
        tree = ast.parse(code)
    except SyntaxError as e:
        yield make_issue(
            filename=file_path,
            line=getattr(e, 'lineno', 0),
            rule="Syntax Error",
            function="N/A",
            severity="ERROR",
            message=f"Failed to parse code: {str(e)}",
            recommendation="Fix syntax errors before scanning",
            category="PARSING"
        )
        return
    
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent
    
    detector = detector_factory(file_path)
    detector.visit(tree)
    
    yield from detector.issues


if __name__ == "__main__":
    sample_code = '''
import os

# CRITICAL: Security-related asserts
def check_user_access(user, resource):
    assert user.is_authenticated, "User must be authenticated"
    assert user.has_permission(resource), "Access denied"
    return resource.data

def verify_admin(user):
    assert user.role == "admin", "Admin required"
    assert user.is_authorized, "Not authorized"

def check_token(token):
    assert token is not None, "Token required"
    assert verify_jwt(token), "Invalid token"

# HIGH: Validation-related asserts
def process_data(data):
    assert data is not None, "Data required"
    assert len(data) > 0, "Data cannot be empty"
    assert isinstance(data, dict), "Data must be a dict"

def validate_email(email):
    assert "@" in email, "Invalid email format"
    assert len(email) <= 255, "Email too long"

def check_range(value):
    assert 0 <= value <= 100, "Value out of range"

# MEDIUM: Type checking asserts
def calculate(x, y):
    assert isinstance(x, (int, float))
    assert isinstance(y, (int, float))
    return x + y

def process_list(items):
    assert type(items) == list
    return sum(items)

# LOW: Generic asserts in production
def do_something(config):
    assert config
    assert "key" in config
    return config["key"]

# OK: Asserts in test functions (should not be flagged)
def test_user_creation():
    user = create_user()
    assert user is not None
    assert user.name == "test"

class TestUserService:
    def test_get_user(self):
        assert get_user(1) is not None

# OK: Debug context (should not be flagged or lower severity)
def debug_helper():
    assert False, "Debug breakpoint"

def _assert_invariant(obj):
    assert obj.is_valid()
'''

    print("Assert Usage Detection Report")
    print("=" * 80)
    
    issues_by_severity = {
        'CRITICAL': [],
        'HIGH': [],
        'MEDIUM': [],
        'LOW': [],
        'INFO': []
    }
    
    for issue in run_detector_with_options(
        lambda fp: AssertDetector(fp, check_tests=False),
        sample_code,
        "sample.py"
    ):
        issues_by_severity[issue.severity].append(issue)
    
    total = sum(len(issues) for issues in issues_by_severity.values())
    print(f"\nTotal Issues Found: {total}\n")
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if issues_by_severity[severity]:
            print(f"\n{severity} Issues ({len(issues_by_severity[severity])}):")
            print("-" * 80)
            for issue in issues_by_severity[severity]:
                print(f"\n  Line {issue.line}:")
                print(f"  Message: {issue.message}")
                print(f"  Recommendation: {issue.recommendation}")