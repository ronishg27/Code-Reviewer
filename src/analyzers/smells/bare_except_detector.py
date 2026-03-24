import ast
from typing import Iterable, Set, List, Optional, Tuple
from dataclasses import dataclass

from src.analyzers.security.base import BaseDetector, Rule, Severity, run_detector
from src.models import make_issue, Issue


class BareExceptDetector(BaseDetector):
    """
    Detector for bare except clauses and overly broad exception handling.
    
    Bare except clauses catch ALL exceptions including:
    - SystemExit (prevents clean shutdown)
    - KeyboardInterrupt (prevents Ctrl+C)
    - MemoryError (masks critical issues)
    - SyntaxError (hides programming errors)
    
    This can mask bugs, security issues, and make debugging extremely difficult.
    """
    
    DETECTOR_NAME = "Bare Except Detector"
    DETECTOR_RULE = "Improper Exception Handling"
    
    # System exceptions that should rarely be caught
    SYSTEM_EXCEPTIONS: Set[str] = {
        'SystemExit', 'KeyboardInterrupt', 'GeneratorExit',
        'SystemError', 'MemoryError'
    }
    
    # Broad exceptions that are often misused
    BROAD_EXCEPTIONS: Set[str] = {
        'Exception', 'BaseException'
    }
    
    # Acceptable broad catches in specific contexts
    ACCEPTABLE_CONTEXTS: Set[str] = {
        'main', '__main__', 'run', 'start', 'execute',
        'worker', 'task', 'job', 'handler', 'wrapper'
    }
    
    def __init__(self, file_path: str = "UNKNOWN"):
        super().__init__(file_path)
        self.bare_except_count = 0
        self.broad_except_count = 0
    
    def visit_Try(self, node: ast.Try) -> None:
        """Analyze try-except blocks."""
        for handler in node.handlers:
            self._check_exception_handler(handler, node)
        
        self.generic_visit(node)
    
    def _check_exception_handler(
        self,
        handler: ast.ExceptHandler,
        try_node: ast.Try
    ) -> None:
        """Check a single exception handler."""
        # Case 1: Bare except (no exception type specified)
        if handler.type is None:
            self._report_bare_except(handler, try_node)
            return
        
        # Get the exception type(s)
        exception_types = self._extract_exception_types(handler.type)
        
        # Case 2: Catching BaseException
        if 'BaseException' in exception_types:
            self._report_base_exception(handler, exception_types)
            return
        
        # Case 3: Catching broad Exception
        if 'Exception' in exception_types:
            self._check_broad_exception(handler, try_node, exception_types)
        
        # Case 4: Catching system exceptions
        system_caught = exception_types.intersection(self.SYSTEM_EXCEPTIONS)
        if system_caught:
            self._report_system_exception(handler, system_caught)
        
        # Case 5: Empty except block (suppresses errors)
        if self._is_empty_handler(handler):
            self._report_empty_handler(handler, exception_types)
        
        # Case 6: Generic except with pass
        if self._has_only_pass(handler):
            self._report_pass_only(handler, exception_types)
    
    def _extract_exception_types(self, exc_type: ast.AST) -> Set[str]:
        """Extract exception type names from the AST node."""
        types = set()
        
        if isinstance(exc_type, ast.Name):
            types.add(exc_type.id)
        elif isinstance(exc_type, ast.Attribute):
            types.add(exc_type.attr)
        elif isinstance(exc_type, ast.Tuple):
            for elt in exc_type.elts:
                types.update(self._extract_exception_types(elt))
        
        return types
    
    def _is_empty_handler(self, handler: ast.ExceptHandler) -> bool:
        """Check if the exception handler is empty or only contains comments."""
        if not handler.body:
            return True
        
        # Check if only contains Pass, Ellipsis, or docstrings
        for stmt in handler.body:
            if isinstance(stmt, (ast.Pass, ast.Expr)):
                if isinstance(stmt, ast.Expr):
                    if not isinstance(stmt.value, ast.Constant):
                        return False
            else:
                return False
        
        return True
    
    def _has_only_pass(self, handler: ast.ExceptHandler) -> bool:
        """Check if handler only contains pass statement."""
        return (
            len(handler.body) == 1 and
            isinstance(handler.body[0], ast.Pass)
        )
    
    def _is_logging_or_re_raising(self, handler: ast.ExceptHandler) -> bool:
        """Check if the handler logs the error or re-raises."""
        for stmt in handler.body:
            # Check for raise statement (re-raising)
            if isinstance(stmt, ast.Raise):
                return True
            
            # Check for logging calls
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Call):
                func_name = self._get_call_name(stmt.value)
                if func_name:
                    logging_methods = {
                        'log', 'debug', 'info', 'warning', 'error',
                        'critical', 'exception', 'print'
                    }
                    if any(method in func_name.lower() for method in logging_methods):
                        return True
        
        return False
    
    def _get_call_name(self, call: ast.Call) -> Optional[str]:
        """Get the name of a function call."""
        if isinstance(call.func, ast.Name):
            return call.func.id
        elif isinstance(call.func, ast.Attribute):
            return call.func.attr
        return None
    
    def _is_acceptable_context(self) -> bool:
        """Check if broad exception catching is acceptable in this context."""
        if self.current_function:
            func_lower = self.current_function.lower()
            for context in self.ACCEPTABLE_CONTEXTS:
                if context in func_lower:
                    return True
        return False
    
    def _report_bare_except(
        self,
        handler: ast.ExceptHandler,
        try_node: ast.Try
    ) -> None:
        """Report a bare except clause."""
        self.bare_except_count += 1
        
        context = self.get_context_string()
        
        # Check if it's suppressing exceptions
        if self._is_empty_handler(handler) or self._has_only_pass(handler):
            severity = Severity.CRITICAL
            message = f"Bare except clause silently suppresses ALL exceptions including SystemExit and KeyboardInterrupt{context}"
            recommendation = "Catch specific exceptions. Never use bare except with pass. If you must catch all, use 'except Exception as e:' and log the error."
        else:
            severity = Severity.HIGH
            message = f"Bare except clause catches ALL exceptions including system exceptions{context}"
            recommendation = "Replace with 'except Exception as e:' to catch only non-system exceptions, or catch specific exception types."
        
        rule = Rule(
            severity=severity,
            message=message,
            recommendation=recommendation
        )
        
        self.report_issue(handler, rule, "except")
    
    def _report_base_exception(
        self,
        handler: ast.ExceptHandler,
        exception_types: Set[str]
    ) -> None:
        """Report catching BaseException."""
        context = self.get_context_string()
        
        if self._is_empty_handler(handler) or self._has_only_pass(handler):
            severity = Severity.CRITICAL
        else:
            severity = Severity.HIGH
        
        rule = Rule(
            severity=severity,
            message=f"Catching BaseException catches system exceptions like SystemExit and KeyboardInterrupt{context}",
            recommendation="Use 'except Exception:' instead to avoid catching system exceptions, or catch specific exceptions."
        )
        
        self.report_issue(handler, rule, "except BaseException")
    
    def _check_broad_exception(
        self,
        handler: ast.ExceptHandler,
        try_node: ast.Try,
        exception_types: Set[str]
    ) -> None:
        """Check if catching Exception is appropriate."""
        context = self.get_context_string()
        
        # If it's empty or just pass, it's very bad
        if self._is_empty_handler(handler) or self._has_only_pass(handler):
            rule = Rule(
                severity=Severity.HIGH,
                message=f"Broad 'except Exception' silently suppresses all errors{context}",
                recommendation="Catch specific exceptions, or at minimum log the error before suppressing it."
            )
            self.report_issue(handler, rule, "except Exception")
            return
        
        # If it's logging or re-raising, check context
        if self._is_logging_or_re_raising(handler):
            if self._is_acceptable_context():
                # Acceptable: top-level handler that logs
                return
            else:
                # Medium severity: logs but might be too broad
                rule = Rule(
                    severity=Severity.MEDIUM,
                    message=f"Broad 'except Exception' may catch unexpected errors{context}",
                    recommendation="Consider catching more specific exceptions if possible."
                )
                self.report_issue(handler, rule, "except Exception")
        else:
            # High severity: broad catch without logging
            rule = Rule(
                severity=Severity.HIGH,
                message=f"Broad 'except Exception' without logging or re-raising{context}",
                recommendation="Catch specific exceptions, or log the error for debugging."
            )
            self.report_issue(handler, rule, "except Exception")
    
    def _report_system_exception(
        self,
        handler: ast.ExceptHandler,
        system_exceptions: Set[str]
    ) -> None:
        """Report catching system exceptions."""
        context = self.get_context_string()
        exceptions_str = ', '.join(sorted(system_exceptions))
        
        rule = Rule(
            severity=Severity.HIGH,
            message=f"Catching system exception(s): {exceptions_str}{context}",
            recommendation=f"Avoid catching {exceptions_str}. These are system-level exceptions that should propagate."
        )
        
        self.report_issue(handler, rule, f"except {exceptions_str}")
    
    def _report_empty_handler(
        self,
        handler: ast.ExceptHandler,
        exception_types: Set[str]
    ) -> None:
        """Report empty exception handler."""
        context = self.get_context_string()
        types_str = ', '.join(sorted(exception_types))
        
        rule = Rule(
            severity=Severity.MEDIUM,
            message=f"Empty except handler for {types_str}{context}",
            recommendation="Add error handling, logging, or remove the try-except if errors should propagate."
        )
        
        self.report_issue(handler, rule, f"except {types_str}")
    
    def _report_pass_only(
        self,
        handler: ast.ExceptHandler,
        exception_types: Set[str]
    ) -> None:
        """Report exception handler with only pass."""
        context = self.get_context_string()
        types_str = ', '.join(sorted(exception_types))
        
        rule = Rule(
            severity=Severity.MEDIUM,
            message=f"Exception handler for {types_str} only contains 'pass'{context}",
            recommendation="Add error handling, logging, or remove if errors should propagate. Document why errors are being suppressed."
        )
        
        self.report_issue(handler, rule, f"except {types_str}")
    
    def _on_call(self, node: ast.Call, func_name: str, resolved_name: str) -> None:
        """Not used for this detector."""
        pass


def detect_bare_except(code: str, file_path: str = "UNKNOWN") -> Iterable[Issue]:
    """Detect bare except and improper exception handling."""
    yield from run_detector(BareExceptDetector, code, file_path)


if __name__ == "__main__":
    sample_code = '''
import logging

# CRITICAL: Bare except with pass (silences everything including Ctrl+C)
def bad_function1():
    try:
        risky_operation()
    except:
        pass  # CRITICAL - silences SystemExit, KeyboardInterrupt, etc.

# CRITICAL: Bare except suppressing all errors
def bad_function2():
    try:
        process_data()
    except:  # CRITICAL - no exception type
        return None

# HIGH: Catching BaseException
def bad_function3():
    try:
        do_something()
    except BaseException:  # HIGH - catches system exceptions
        print("Error occurred")

# HIGH: Broad Exception with pass
def bad_function4():
    try:
        parse_input()
    except Exception:  # HIGH - too broad and silent
        pass

# HIGH: Broad Exception without logging
def bad_function5():
    try:
        validate_data()
    except Exception:  # HIGH - no logging
        return False

# MEDIUM: Broad Exception with logging (but might be too broad)
def questionable_function():
    try:
        complex_operation()
    except Exception as e:  # MEDIUM - logs but still broad
        logging.error(f"Operation failed: {e}")
        return None

# MEDIUM: Empty handler for specific exception
def mediocre_function():
    try:
        open_file()
    except FileNotFoundError:  # MEDIUM - empty handler
        ...

# MEDIUM: Pass-only handler
def another_mediocre():
    try:
        connect()
    except ConnectionError:  # MEDIUM - only pass
        pass

# HIGH: Catching SystemExit
def very_bad():
    try:
        sys.exit(1)
    except SystemExit:  # HIGH - catching system exception
        continue_running()

# OK: Acceptable in main() with logging
def main():
    try:
        run_application()
    except Exception as e:  # OK - top-level with logging
        logging.exception("Application error")
        sys.exit(1)

# OK: Specific exception
def good_function1():
    try:
        read_config()
    except (FileNotFoundError, PermissionError) as e:  # OK - specific
        logging.error(f"Config error: {e}")
        use_defaults()

# OK: Re-raising after logging
def good_function2():
    try:
        critical_operation()
    except Exception as e:  # OK - re-raises
        logging.error(f"Critical error: {e}")
        raise

# OK: Specific handling
def good_function3():
    try:
        value = int(user_input)
    except ValueError:  # OK - specific exception
        value = 0
'''

    print("Bare Except Detection Report")
    print("=" * 80)
    
    issues_by_severity = {
        'CRITICAL': [],
        'HIGH': [],
        'MEDIUM': [],
        'LOW': [],
    }
    
    for issue in detect_bare_except(sample_code, "sample.py"):
        issues_by_severity[issue.severity].append(issue)
    
    total = sum(len(issues) for issues in issues_by_severity.values())
    print(f"\nTotal Issues Found: {total}\n")
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        if issues_by_severity[severity]:
            print(f"\n{severity} Issues ({len(issues_by_severity[severity])}):")
            print("-" * 80)
            for issue in issues_by_severity[severity]:
                print(f"\n  Line {issue.line}:")
                print(f"  Message: {issue.message}")
                print(f"  Recommendation: {issue.recommendation}")
    
    print("\n" + "=" * 80)
    print("\nEXCEPTION HANDLING BEST PRACTICES:")
    print("-" * 80)
    print("""
❌ NEVER DO:
  try:
      code()
  except:  # Bare except - catches EVERYTHING
      pass

❌ AVOID:
  except BaseException:  # Catches system exceptions
  except Exception:      # Too broad (usually)

✅ GOOD:
  except (ValueError, TypeError) as e:  # Specific exceptions
      logging.error(f"Error: {e}")

✅ ACCEPTABLE (in main/top-level only):
  except Exception as e:
      logging.exception("Application error")
      raise  # or sys.exit(1)

SYSTEM EXCEPTIONS (never catch):
  • SystemExit - prevents clean shutdown
  • KeyboardInterrupt - prevents Ctrl+C
  • GeneratorExit - breaks generators
  • MemoryError - masks critical issues
""")