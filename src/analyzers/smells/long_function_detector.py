import ast
from typing import Optional

from src.analyzers.security.base import BaseDetector, Rule, Severity, run_detector
from src.models import make_issue, Issue


class LongFunctionDetector(BaseDetector):
    """
    Detector for excessively long functions.
    
    Long functions:
    - Violate Single Responsibility Principle
    - Are hard to understand and test
    - Often contain multiple levels of abstraction
    - Are difficult to reuse
    
    Industry standards:
    - Warning: 50+ lines
    - High: 100+ lines
    - Critical: 200+ lines
    """
    
    DETECTOR_NAME = "Long Function Detector"
    DETECTOR_RULE = "Excessive Function Length"
    
    # Thresholds (in lines of code, excluding comments and docstrings)
    WARNING_THRESHOLD = 50
    HIGH_THRESHOLD = 100
    CRITICAL_THRESHOLD = 200
    
    # Also track logical lines (statements)
    STATEMENT_WARNING = 30
    STATEMENT_HIGH = 60
    STATEMENT_CRITICAL = 100
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyze function length."""
        old_function = self.current_function
        self.current_function = node.name
        
        # Calculate metrics
        physical_lines = self._count_physical_lines(node)
        logical_lines = self._count_statements(node)
        complexity_score = self._calculate_complexity(node)
        
        # Check thresholds
        self._check_function_length(
            node,
            physical_lines,
            logical_lines,
            complexity_score
        )
        
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Analyze async function length."""
        self.visit_FunctionDef(node)
    
    def _count_physical_lines(self, node: ast.FunctionDef) -> int:
        """Count physical lines of code (excluding docstring)."""
        if not node.body:
            return 0
        
        # Get first and last line
        first_line = node.body[0].lineno
        
        # Skip docstring if present
        if (isinstance(node.body[0], ast.Expr) and
            isinstance(node.body[0].value, ast.Constant) and
            isinstance(node.body[0].value.value, str)):
            if len(node.body) > 1:
                first_line = node.body[1].lineno
            else:
                return 1
        
        # Find the last line
        last_line = self._get_last_line(node.body[-1])
        
        return last_line - first_line + 1
    
    def _get_last_line(self, node: ast.AST) -> int:
        """Get the last line number of a node."""
        last = node.lineno
        
        for child in ast.walk(node):
            if hasattr(child, 'lineno'):
                last = max(last, child.lineno)
            if hasattr(child, 'end_lineno') and child.end_lineno:
                last = max(last, child.end_lineno)
        
        return last
    
    def _count_statements(self, node: ast.FunctionDef) -> int:
        """Count logical lines (statements)."""
        count = 0
        
        for child in ast.walk(node):
            if isinstance(child, (
                ast.Assign, ast.AugAssign, ast.AnnAssign,
                ast.Return, ast.Raise, ast.Assert,
                ast.Import, ast.ImportFrom,
                ast.Expr, ast.Pass, ast.Break, ast.Continue,
                ast.Delete, ast.Global, ast.Nonlocal
            )):
                count += 1
        
        return count
    
    def _calculate_complexity(self, node: ast.FunctionDef) -> int:
        """Calculate a simple complexity score based on control flow."""
        complexity = 1  # Base complexity
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.For, ast.While, ast.Try)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                # And/Or in conditions
                complexity += len(child.values) - 1
        
        return complexity
    
    def _check_function_length(
        self,
        node: ast.FunctionDef,
        physical_lines: int,
        logical_lines: int,
        complexity: int
    ) -> None:
        """Check if function exceeds length thresholds."""
        # Determine severity based on physical lines
        severity = None
        threshold_name = None
        
        if physical_lines >= self.CRITICAL_THRESHOLD:
            severity = Severity.HIGH
            threshold_name = "critical"
        elif physical_lines >= self.HIGH_THRESHOLD:
            severity = Severity.MEDIUM
            threshold_name = "high"
        elif physical_lines >= self.WARNING_THRESHOLD:
            severity = Severity.LOW
            threshold_name = "warning"
        
        # Also check logical lines
        if logical_lines >= self.STATEMENT_CRITICAL:
            severity = Severity.HIGH
        elif logical_lines >= self.STATEMENT_HIGH and severity != Severity.HIGH:
            severity = Severity.MEDIUM
        elif logical_lines >= self.STATEMENT_WARNING and not severity:
            severity = Severity.LOW
        
        if not severity:
            return
        
        # Build message
        message = (
            f"Function '{node.name}' is too long: "
            f"{physical_lines} lines, {logical_lines} statements, "
            f"complexity {complexity}{self.get_context_string()}"
        )
        
        recommendation = self._get_refactoring_advice(
            physical_lines,
            logical_lines,
            complexity
        )
        
        rule = Rule(
            severity=severity,
            message=message,
            recommendation=recommendation
        )
        
        self.report_issue(node, rule, node.name)
    
    def _get_refactoring_advice(
        self,
        physical_lines: int,
        logical_lines: int,
        complexity: int
    ) -> str:
        """Generate specific refactoring advice."""
        advice = ["Consider refactoring this function:"]
        
        if physical_lines > 150:
            advice.append("• This function is extremely long - split into smaller functions")
        elif physical_lines > 75:
            advice.append("• Extract logical blocks into separate functions")
        else:
            advice.append("• Look for opportunities to extract helper functions")
        
        if complexity > 15:
            advice.append("• High complexity - simplify control flow")
        elif complexity > 10:
            advice.append("• Consider reducing conditional complexity")
        
        advice.extend([
            "• Apply Single Responsibility Principle",
            "• Each function should do one thing well",
            "• Aim for functions under 50 lines"
        ])
        
        return " ".join(advice)
    
    def _on_call(self, node: ast.Call, func_name: str, resolved_name: str) -> None:
        """Not used for this detector."""
        pass


def detect_long_function(code: str, file_path: str = "UNKNOWN"):
    """Detect excessively long functions."""
    yield from run_detector(LongFunctionDetector, code, file_path)


if __name__ == "__main__":
    sample_code = '''
def short_function():
    """This is fine."""
    x = 1
    y = 2
    return x + y

def moderate_function():
    """50-60 lines - warning level."""
    result = []
    # Imagine 50 lines of code here
    for i in range(10):
        if i % 2 == 0:
            result.append(i)
        else:
            result.append(-i)
    
    for i in range(10):
        if i % 3 == 0:
            result.append(i * 2)
    
    for i in range(10):
        if i % 5 == 0:
            result.append(i * 3)
    
    total = sum(result)
    average = total / len(result)
    
    if average > 10:
        result = [x * 2 for x in result]
    elif average > 5:
        result = [x * 1.5 for x in result]
    
    return result

def very_long_function():
    """100+ lines - high severity."""
    # This would have 100+ lines of actual code
    data = []
    
    # Section 1: Data preparation (20 lines)
    for i in range(100):
        if i % 2 == 0:
            data.append({"id": i, "value": i * 2})
        else:
            data.append({"id": i, "value": i * 3})
    
    # Section 2: Data validation (20 lines)
    valid_data = []
    for item in data:
        if item["value"] > 0:
            if item["id"] % 3 == 0:
                valid_data.append(item)
            elif item["id"] % 5 == 0:
                valid_data.append(item)
    
    # Section 3: Data transformation (20 lines)
    transformed = []
    for item in valid_data:
        new_item = {}
        new_item["original_id"] = item["id"]
        new_item["transformed_value"] = item["value"] * 2
        new_item["category"] = "even" if item["id"] % 2 == 0 else "odd"
        transformed.append(new_item)
    
    # Section 4: Aggregation (20 lines)
    categories = {}
    for item in transformed:
        cat = item["category"]
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(item)
    
    # Section 5: Final processing (20 lines)
    results = {}
    for cat, items in categories.items():
        total = sum(i["transformed_value"] for i in items)
        avg = total / len(items)
        results[cat] = {
            "total": total,
            "average": avg,
            "count": len(items)
        }
    
    return results
'''

    print("Long Function Detection Report")
    print("=" * 80)
    
    for issue in detect_long_function(sample_code, "sample.py"):
        print(f"\nLine {issue.line}: {issue.function}")
        print(f"Severity: {issue.severity}")
        print(f"Message: {issue.message}")
        print(f"Recommendation: {issue.recommendation}")