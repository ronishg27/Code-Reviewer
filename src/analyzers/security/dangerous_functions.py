import ast
from typing import Dict, Iterable, Set, List, Optional
from dataclasses import dataclass

from src.analyzers.security.base import BaseDetector, Rule, Severity, run_detector
from src.models import make_issue, Issue


@dataclass
class DangerousFunctionRule:
    """Rule for a dangerous function."""
    severity: Severity
    message: str
    recommendation: str
    requires_dynamic_input: bool = False
    safe_if_literal: bool = False


class DangerousFunctionsDetector(BaseDetector):
    """
    Detector for dangerous function usage.
    
    Detects functions that can lead to:
    - Code execution vulnerabilities
    - Path traversal vulnerabilities
    - Information disclosure
    - Unsafe reflection/introspection
    """
    
    DETECTOR_NAME = "Dangerous Functions Detector"
    DETECTOR_RULE = "Dangerous Function Usage"
    
    # Code execution functions
    CODE_EXECUTION_FUNCTIONS: Dict[str, DangerousFunctionRule] = {
        'eval': DangerousFunctionRule(
            severity=Severity.CRITICAL,
            message="eval() executes arbitrary Python code",
            recommendation="Use ast.literal_eval() for safe literal evaluation, or avoid eval entirely"
        ),
        'exec': DangerousFunctionRule(
            severity=Severity.CRITICAL,
            message="exec() executes arbitrary Python code",
            recommendation="Refactor to avoid exec. Use importlib for dynamic imports, or dispatch tables for dynamic behavior"
        ),
        'compile': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="compile() can create code objects that may be executed with eval/exec",
            recommendation="Avoid compiling untrusted code. If necessary, use a sandboxed environment"
        ),
        '__import__': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="__import__() allows dynamic imports which can load malicious modules",
            recommendation="Use importlib.import_module() with strict allowlisting of module names"
        ),
        'importlib.import_module': DangerousFunctionRule(
            severity=Severity.MEDIUM,
            message="Dynamic imports can load unexpected modules if input is not validated",
            recommendation="Validate module names against an allowlist before importing",
            requires_dynamic_input=True
        ),
    }
    
    # Reflection/introspection functions
    REFLECTION_FUNCTIONS: Dict[str, DangerousFunctionRule] = {
        'getattr': DangerousFunctionRule(
            severity=Severity.MEDIUM,
            message="getattr() with dynamic attribute names can access unintended attributes",
            recommendation="Validate attribute names against an allowlist, or use a dispatch dict",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'setattr': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="setattr() with dynamic attribute names can modify unintended attributes",
            recommendation="Validate attribute names against an allowlist before setting",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'delattr': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="delattr() with dynamic attribute names can delete critical attributes",
            recommendation="Validate attribute names against an allowlist before deleting",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'globals': DangerousFunctionRule(
            severity=Severity.MEDIUM,
            message="globals() provides access to global namespace, allowing modification of global state",
            recommendation="Avoid using globals() for dynamic variable access. Use explicit dictionaries instead"
        ),
        'locals': DangerousFunctionRule(
            severity=Severity.LOW,
            message="locals() provides access to local namespace",
            recommendation="Avoid using locals() for dynamic variable access. Use explicit dictionaries instead"
        ),
        'vars': DangerousFunctionRule(
            severity=Severity.LOW,
            message="vars() provides access to object's __dict__",
            recommendation="Use explicit attribute access or getattr() with validation"
        ),
    }
    
    # File system functions with path traversal risks
    FILESYSTEM_FUNCTIONS: Dict[str, DangerousFunctionRule] = {
        'open': DangerousFunctionRule(
            severity=Severity.MEDIUM,
            message="open() with user-controlled paths can lead to path traversal",
            recommendation="Validate and sanitize file paths. Use os.path.realpath() and check against allowed directories",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'os.open': DangerousFunctionRule(
            severity=Severity.MEDIUM,
            message="os.open() with user-controlled paths can lead to path traversal",
            recommendation="Validate and sanitize file paths. Use os.path.realpath() and check against allowed directories",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'os.remove': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="os.remove() with user-controlled paths can delete arbitrary files",
            recommendation="Validate paths against an allowlist. Use os.path.realpath() to prevent traversal",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'os.unlink': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="os.unlink() with user-controlled paths can delete arbitrary files",
            recommendation="Validate paths against an allowlist. Use os.path.realpath() to prevent traversal",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'os.rmdir': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="os.rmdir() with user-controlled paths can delete arbitrary directories",
            recommendation="Validate paths against an allowlist. Use os.path.realpath() to prevent traversal",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'os.rename': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="os.rename() with user-controlled paths can move/rename arbitrary files",
            recommendation="Validate both source and destination paths against allowlists",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'os.chmod': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="os.chmod() with user-controlled paths can change permissions on arbitrary files",
            recommendation="Validate paths against an allowlist before changing permissions",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'os.chown': DangerousFunctionRule(
            severity=Severity.CRITICAL,
            message="os.chown() with user-controlled paths can change ownership of arbitrary files",
            recommendation="Validate paths against an allowlist. Avoid using with user input",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'shutil.rmtree': DangerousFunctionRule(
            severity=Severity.CRITICAL,
            message="shutil.rmtree() can recursively delete entire directory trees",
            recommendation="Validate paths strictly. Use os.path.realpath() and check against allowed base directories",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'shutil.copy': DangerousFunctionRule(
            severity=Severity.MEDIUM,
            message="shutil.copy() with user-controlled paths can copy files to/from arbitrary locations",
            recommendation="Validate both source and destination paths against allowlists",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'shutil.copy2': DangerousFunctionRule(
            severity=Severity.MEDIUM,
            message="shutil.copy2() with user-controlled paths can copy files to/from arbitrary locations",
            recommendation="Validate both source and destination paths against allowlists",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'shutil.copytree': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="shutil.copytree() can copy entire directory trees",
            recommendation="Validate paths strictly against allowlists",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'shutil.move': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="shutil.move() with user-controlled paths can move files to/from arbitrary locations",
            recommendation="Validate both source and destination paths against allowlists",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'pathlib.Path.unlink': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="Path.unlink() with user-controlled paths can delete arbitrary files",
            recommendation="Validate paths against an allowlist before deleting",
            requires_dynamic_input=True
        ),
        'pathlib.Path.rmdir': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="Path.rmdir() with user-controlled paths can delete arbitrary directories",
            recommendation="Validate paths against an allowlist before deleting",
            requires_dynamic_input=True
        ),
    }
    
    # Web framework dangerous functions
    WEB_FRAMEWORK_FUNCTIONS: Dict[str, DangerousFunctionRule] = {
        'send_file': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="send_file() with user-controlled paths can lead to arbitrary file disclosure",
            recommendation="Validate file paths against an allowlist. Use send_from_directory() with a safe base path",
            requires_dynamic_input=True
        ),
        'flask.send_file': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="Flask send_file() with user-controlled paths can disclose arbitrary files",
            recommendation="Use send_from_directory() with a validated filename and safe directory",
            requires_dynamic_input=True
        ),
        'flask.send_from_directory': DangerousFunctionRule(
            severity=Severity.MEDIUM,
            message="send_from_directory() can still be vulnerable if directory is user-controlled",
            recommendation="Ensure the directory parameter is not user-controlled. Validate filenames",
            requires_dynamic_input=True
        ),
        'django.http.FileResponse': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="FileResponse with user-controlled paths can disclose arbitrary files",
            recommendation="Validate file paths against an allowlist before serving",
            requires_dynamic_input=True
        ),
        'make_response': DangerousFunctionRule(
            severity=Severity.LOW,
            message="make_response() with user-controlled content may lead to XSS",
            recommendation="Ensure proper content-type headers and escape user content",
            requires_dynamic_input=True
        ),
    }
    
    # Unsafe serialization (complement to deserialization detector)
    SERIALIZATION_FUNCTIONS: Dict[str, DangerousFunctionRule] = {
        'pickle.dumps': DangerousFunctionRule(
            severity=Severity.LOW,
            message="pickle.dumps() creates data that could be maliciously modified before loading",
            recommendation="Use JSON for data interchange. If pickle is required, use HMAC to verify integrity"
        ),
        'pickle.dump': DangerousFunctionRule(
            severity=Severity.LOW,
            message="pickle.dump() creates data that could be maliciously modified before loading",
            recommendation="Use JSON for data interchange. If pickle is required, use HMAC to verify integrity"
        ),
    }
    
    # Network functions with SSRF potential
    NETWORK_FUNCTIONS: Dict[str, DangerousFunctionRule] = {
        'urllib.request.urlopen': DangerousFunctionRule(
            severity=Severity.MEDIUM,
            message="urlopen() with user-controlled URLs can lead to SSRF",
            recommendation="Validate URLs against an allowlist of domains. Block internal/private IPs",
            requires_dynamic_input=True
        ),
        'requests.get': DangerousFunctionRule(
            severity=Severity.MEDIUM,
            message="requests.get() with user-controlled URLs can lead to SSRF",
            recommendation="Validate URLs against an allowlist of domains. Block internal/private IPs",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'requests.post': DangerousFunctionRule(
            severity=Severity.MEDIUM,
            message="requests.post() with user-controlled URLs can lead to SSRF",
            recommendation="Validate URLs against an allowlist of domains. Block internal/private IPs",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'requests.request': DangerousFunctionRule(
            severity=Severity.MEDIUM,
            message="requests.request() with user-controlled URLs can lead to SSRF",
            recommendation="Validate URLs against an allowlist of domains. Block internal/private IPs",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'httpx.get': DangerousFunctionRule(
            severity=Severity.MEDIUM,
            message="httpx.get() with user-controlled URLs can lead to SSRF",
            recommendation="Validate URLs against an allowlist of domains. Block internal/private IPs",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'httpx.post': DangerousFunctionRule(
            severity=Severity.MEDIUM,
            message="httpx.post() with user-controlled URLs can lead to SSRF",
            recommendation="Validate URLs against an allowlist of domains. Block internal/private IPs",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
        'aiohttp.ClientSession.get': DangerousFunctionRule(
            severity=Severity.MEDIUM,
            message="aiohttp request with user-controlled URLs can lead to SSRF",
            recommendation="Validate URLs against an allowlist of domains. Block internal/private IPs",
            requires_dynamic_input=True,
            safe_if_literal=True
        ),
    }
    
    # Dangerous builtins
    DANGEROUS_BUILTINS: Dict[str, DangerousFunctionRule] = {
        'input': DangerousFunctionRule(
            severity=Severity.INFO,
            message="input() in Python 2 was eval(raw_input()). Ensure Python 3 is used",
            recommendation="Use Python 3 where input() is safe, or explicitly use raw_input() in Python 2"
        ),
        'breakpoint': DangerousFunctionRule(
            severity=Severity.LOW,
            message="breakpoint() should not be in production code",
            recommendation="Remove breakpoint() calls before deploying to production"
        ),
        'exit': DangerousFunctionRule(
            severity=Severity.LOW,
            message="exit() should not be used in production code",
            recommendation="Use sys.exit() with proper error handling, or raise SystemExit"
        ),
        'quit': DangerousFunctionRule(
            severity=Severity.LOW,
            message="quit() should not be used in production code",
            recommendation="Use sys.exit() with proper error handling, or raise SystemExit"
        ),
    }
    
    # Low-level and memory functions
    LOWLEVEL_FUNCTIONS: Dict[str, DangerousFunctionRule] = {
        'ctypes.cast': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="ctypes.cast() can lead to memory corruption if misused",
            recommendation="Ensure proper type validation. Avoid with untrusted data"
        ),
        'ctypes.pointer': DangerousFunctionRule(
            severity=Severity.MEDIUM,
            message="ctypes.pointer() allows low-level memory manipulation",
            recommendation="Use with caution. Validate all inputs"
        ),
        'ctypes.CDLL': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="Loading shared libraries can execute arbitrary code",
            recommendation="Only load trusted libraries. Validate library paths",
            requires_dynamic_input=True
        ),
        'ctypes.WinDLL': DangerousFunctionRule(
            severity=Severity.HIGH,
            message="Loading DLLs can execute arbitrary code",
            recommendation="Only load trusted DLLs. Validate DLL paths",
            requires_dynamic_input=True
        ),
    }
    
    def __init__(self, file_path: str = "UNKNOWN"):
        super().__init__(file_path)
        # Combine all function rules
        self.all_rules: Dict[str, DangerousFunctionRule] = {}
        self.all_rules.update(self.CODE_EXECUTION_FUNCTIONS)
        self.all_rules.update(self.REFLECTION_FUNCTIONS)
        self.all_rules.update(self.FILESYSTEM_FUNCTIONS)
        self.all_rules.update(self.WEB_FRAMEWORK_FUNCTIONS)
        self.all_rules.update(self.SERIALIZATION_FUNCTIONS)
        self.all_rules.update(self.NETWORK_FUNCTIONS)
        self.all_rules.update(self.DANGEROUS_BUILTINS)
        self.all_rules.update(self.LOWLEVEL_FUNCTIONS)
    
    def _on_call(self, node: ast.Call, func_name: str, resolved_name: str) -> None:
        """Check function calls for dangerous functions."""

        try: 
            # Check both the original name and resolved name
            rule = self.all_rules.get(resolved_name) or self.all_rules.get(func_name)
            
            if not rule:
                # Check for partial matches (e.g., "pathlib.Path.unlink" matches "unlink")
                for rule_name, r in self.all_rules.items():
                    if resolved_name.endswith(f".{rule_name.split('.')[-1]}"):
                        rule = r
                        break
            
            if not rule:
                return
            
            # Check if the function requires dynamic input to be dangerous
            if rule.requires_dynamic_input:
                if not self._has_dynamic_input(node):
                    return
            
            # Check if the function is safe with literal arguments
            if rule.safe_if_literal:
                if self._has_only_literal_args(node):
                    return
            
            # Report the issue
            context = self.get_context_string()
            additional = f" {context}" if context else ""
            
            report_rule = Rule(
                severity=rule.severity,
                message=f"{rule.message}{additional}",
                recommendation=rule.recommendation
            )
            
            self.report_issue(node, report_rule, func_name)


        except Exception as e:
            import logging
            logging.warning(f"Dangerous functions detector error at line {node.lineno}: {e}")
            return
    
    def _has_dynamic_input(self, node: ast.Call) -> bool:
        """Check if the function call has dynamic (non-literal) input."""
        # Check all positional arguments
        for arg in node.args:
            if not self._is_literal(arg):
                return True
        
        # Check keyword arguments
        for keyword in node.keywords:
            if not self._is_literal(keyword.value):
                return True
        
        return False
    
    def _has_only_literal_args(self, node: ast.Call) -> bool:
        """Check if all arguments are literals."""
        for arg in node.args:
            if not self._is_literal(arg):
                return False
        
        for keyword in node.keywords:
            if not self._is_literal(keyword.value):
                return False
        
        return True
    
    def _is_literal(self, node: ast.AST) -> bool:
        """Check if a node is a literal value."""
        if isinstance(node, ast.Constant):
            return True
        
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return all(self._is_literal(el) for el in node.elts)
        
        if isinstance(node, ast.Dict):
            return (
                all(self._is_literal(k) for k in node.keys if k is not None) and
                all(self._is_literal(v) for v in node.values)
            )
        
        # f-strings are not literals
        if isinstance(node, ast.JoinedStr):
            return False
        
        # Check for simple string concatenation of literals
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return self._is_literal(node.left) and self._is_literal(node.right)
        
        return False


def detect_dangerous_functions(code: str, file_path: str = "UNKNOWN") -> Iterable[Issue]:
    """
    Detect dangerous function usage in code.
    
    Args:
        code: The source code to analyze
        file_path: The path of the file being analyzed
        
    Yields:
        Issue objects for each dangerous function usage
    """
    yield from run_detector(DangerousFunctionsDetector, code, file_path)


if __name__ == "__main__":
    sample_code = '''
import os
import shutil
import ctypes
import pickle
import requests
from pathlib import Path

# CRITICAL: Code execution
def process_user_code(code):
    eval(code)  # CRITICAL
    exec(code)  # CRITICAL
    compiled = compile(code, "<string>", "exec")  # HIGH
    exec(compiled)

def dynamic_import(module_name):
    __import__(module_name)  # HIGH
    
# HIGH: Reflection with dynamic input
def get_attribute(obj, attr_name):
    return getattr(obj, attr_name)  # MEDIUM (dynamic)
    
def set_attribute(obj, attr_name, value):
    setattr(obj, attr_name, value)  # HIGH (dynamic)

# OK: Reflection with literal (should not flag)
def get_name(obj):
    return getattr(obj, "name")  # Safe - literal

# HIGH: File system operations with dynamic paths
def delete_file(user_path):
    os.remove(user_path)  # HIGH
    os.unlink(user_path)  # HIGH
    Path(user_path).unlink()  # HIGH
    
def delete_directory(user_path):
    shutil.rmtree(user_path)  # CRITICAL
    os.rmdir(user_path)  # HIGH

def copy_file(src, dst):
    shutil.copy(src, dst)  # MEDIUM
    shutil.move(src, dst)  # HIGH

# OK: File operations with literal paths (should not flag)
def read_config():
    with open("config.json") as f:  # Safe - literal
        return f.read()

# MEDIUM: SSRF potential
def fetch_url(url):
    requests.get(url)  # MEDIUM (dynamic URL)
    requests.post(url, data={})  # MEDIUM

# OK: Request with literal URL (should not flag)
def get_homepage():
    return requests.get("https://example.com")  # Safe - literal

# HIGH: Web framework dangerous functions
def serve_file(filename):
    from flask import send_file
    return send_file(filename)  # HIGH

# MEDIUM: Namespace access
def modify_global(name, value):
    globals()[name] = value  # MEDIUM
    
def inspect_locals():
    return locals()  # LOW

# HIGH: Low-level operations
def load_library(path):
    ctypes.CDLL(path)  # HIGH (dynamic)

# LOW: Production issues
def debug_code():
    breakpoint()  # LOW
    exit()  # LOW

# MEDIUM: Dangerous in some contexts
def get_user_input():
    return input("Enter value: ")  # INFO (Python 3 is safe)

# LOW: Serialization
def save_data(data):
    pickle.dumps(data)  # LOW
'''

    print("Dangerous Functions Detection Report")
    print("=" * 80)
    
    issues_by_severity = {
        'CRITICAL': [],
        'HIGH': [],
        'MEDIUM': [],
        'LOW': [],
        'INFO': []
    }
    
    for issue in detect_dangerous_functions(sample_code, "sample.py"):
        issues_by_severity[issue.severity].append(issue)
    
    total = sum(len(issues) for issues in issues_by_severity.values())
    print(f"\nTotal Issues Found: {total}\n")
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if issues_by_severity[severity]:
            print(f"\n{severity} Issues ({len(issues_by_severity[severity])}):")
            print("-" * 80)
            for issue in issues_by_severity[severity]:
                print(f"\n  Line {issue.line}: {issue.function}")
                print(f"  Message: {issue.message}")
                print(f"  Recommendation: {issue.recommendation}")
    
    print("\n" + "=" * 80)
    print("\nDANGEROUS FUNCTIONS QUICK REFERENCE:")
    print("-" * 80)
    print("""
CODE EXECUTION (Always Dangerous):
  • eval(), exec() -> Use ast.literal_eval() or dispatch tables
  • compile() -> Avoid with untrusted input
  • __import__() -> Use importlib with allowlist

REFLECTION (Dangerous with Dynamic Input):
  • getattr/setattr/delattr -> Validate attribute names
  • globals()/locals() -> Use explicit dictionaries

FILE SYSTEM (Validate Paths):
  • open(), os.remove(), shutil.rmtree() -> Sanitize paths
  • Use os.path.realpath() + base directory check

NETWORK (SSRF Risk):
  • requests.*, urllib.* -> Validate URLs against allowlist
  • Block internal/private IP addresses

WEB FRAMEWORKS:
  • send_file() -> Use send_from_directory() with validation
  • Validate all user-controlled paths
""")