import ast
from typing import Iterable, List, Optional, Set
from dataclasses import dataclass

from src.analyzers.security.base import BaseDetector, Rule, Severity, run_detector
from src.models import make_issue, Issue


@dataclass
class NestingInfo:
    """Information about nesting at a specific point."""
    level: int
    node_type: str
    line: int


class DeepNestingDetector(BaseDetector):
    """
    Detector for excessive nesting depth.
    
    Deep nesting makes code:
    - Hard to read and understand
    - Difficult to test (many code paths)
    - More prone to bugs
    - Hard to maintain
    
    Recommended maximum nesting: 3-4 levels
    """
    
    DETECTOR_NAME = "Deep Nesting Detector"
    DETECTOR_RULE = "Excessive Nesting"
    
    # Nesting thresholds
    WARNING_THRESHOLD = 4  # Warn at this level
    CRITICAL_THRESHOLD = 6  # Critical at this level
    
    # Node types that contribute to nesting
    NESTING_NODES = (
        ast.If, ast.For, ast.While, ast.Try,
        ast.With, ast.ExceptHandler, ast.AsyncFor, ast.AsyncWith
    )
    
    def __init__(self, file_path: str = "UNKNOWN"):
        super().__init__(file_path)
        self.max_nesting = 0
        self.current_nesting = 0
        self.nesting_stack: List[NestingInfo] = []
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Analyze function for nesting depth."""
        old_function = self.current_function
        old_nesting = self.current_nesting
        old_max = self.max_nesting
        old_stack = self.nesting_stack.copy()
        
        self.current_function = node.name
        self.current_nesting = 0
        self.max_nesting = 0
        self.nesting_stack = []
        
        # Visit function body
        for stmt in node.body:
            self.visit(stmt)
        
        # Report if function has deep nesting
        if self.max_nesting >= self.WARNING_THRESHOLD:
            self._report_deep_nesting(node, self.max_nesting)
        
        # Restore state
        self.current_function = old_function
        self.current_nesting = old_nesting
        self.max_nesting = old_max
        self.nesting_stack = old_stack
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Analyze async function for nesting depth."""
        # Same as regular function
        self.visit_FunctionDef(node)
    
    def _visit_nesting_node(self, node: ast.AST, node_type: str) -> None:
        """Visit a node that increases nesting level."""
        self.current_nesting += 1
        self.nesting_stack.append(NestingInfo(
            level=self.current_nesting,
            node_type=node_type,
            line=node.lineno
        ))
        
        if self.current_nesting > self.max_nesting:
            self.max_nesting = self.current_nesting
        
        # Visit children
        self.generic_visit(node)
        
        # Decrease nesting when leaving
        self.current_nesting -= 1
        self.nesting_stack.pop()
    
    def visit_If(self, node: ast.If) -> None:
        """Track if statement nesting."""
        self._visit_nesting_node(node, "if")
    
    def visit_For(self, node: ast.For) -> None:
        """Track for loop nesting."""
        self._visit_nesting_node(node, "for")
    
    def visit_AsyncFor(self, node: ast.AsyncFor) -> None:
        """Track async for loop nesting."""
        self._visit_nesting_node(node, "async for")
    
    def visit_While(self, node: ast.While) -> None:
        """Track while loop nesting."""
        self._visit_nesting_node(node, "while")
    
    def visit_Try(self, node: ast.Try) -> None:
        """Track try block nesting."""
        # Try block increases nesting
        self.current_nesting += 1
        self.nesting_stack.append(NestingInfo(
            level=self.current_nesting,
            node_type="try",
            line=node.lineno
        ))
        
        if self.current_nesting > self.max_nesting:
            self.max_nesting = self.current_nesting
        
        # Visit try body
        for stmt in node.body:
            self.visit(stmt)
        
        # Visit exception handlers (they inherit the try's nesting)
        for handler in node.handlers:
            self.visit(handler)
        
        # Visit else
        for stmt in node.orelse:
            self.visit(stmt)
        
        # Visit finally
        for stmt in node.finalbody:
            self.visit(stmt)
        
        self.current_nesting -= 1
        self.nesting_stack.pop()
    
    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        """Track except handler nesting (doesn't add extra level, inherits from try)."""
        for stmt in node.body:
            self.visit(stmt)
    
    def visit_With(self, node: ast.With) -> None:
        """Track with statement nesting."""
        self._visit_nesting_node(node, "with")
    
    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        """Track async with statement nesting."""
        self._visit_nesting_node(node, "async with")
    
    def _report_deep_nesting(self, node: ast.FunctionDef, max_depth: int) -> None:
        """Report excessive nesting in a function."""
        context = f"in function '{node.name}'"
        
        if max_depth >= self.CRITICAL_THRESHOLD:
            severity = Severity.HIGH
            message = f"Excessive nesting depth of {max_depth} levels {context}"
        else:
            severity = Severity.MEDIUM
            message = f"High nesting depth of {max_depth} levels {context}"
        
        recommendation = self._get_refactoring_suggestions(max_depth)
        
        rule = Rule(
            severity=severity,
            message=message,
            recommendation=recommendation
        )
        
        self.report_issue(node, rule, node.name)
    
    def _get_refactoring_suggestions(self, depth: int) -> str:
        """Get specific refactoring suggestions based on nesting depth."""
        suggestions = [
            "Consider refactoring to reduce nesting depth:",
            "• Extract nested logic into separate functions",
            "• Use early returns/continue to reduce if-else nesting",
            "• Invert conditions to eliminate else blocks",
            "• Use guard clauses at the start of functions",
        ]
        
        if depth >= self.CRITICAL_THRESHOLD:
            suggestions.append("• Consider redesigning the algorithm - this is very complex")
        
        return " ".join(suggestions)
    
    def _on_call(self, node: ast.Call, func_name: str, resolved_name: str) -> None:
        """Not used for this detector."""
        pass


def detect_deep_nesting(code: str, file_path: str = "UNKNOWN") -> Iterable[Issue]:
    """Detect excessive nesting depth in code."""
    yield from run_detector(DeepNestingDetector, code, file_path)


if __name__ == "__main__":
    sample_code = '''
# MEDIUM: Nesting level 4
def moderate_nesting(data):
    if data:                    # Level 1
        for item in data:       # Level 2
            if item.valid:      # Level 3
                try:            # Level 4
                    process(item)
                except Error:
                    log_error()

# HIGH: Nesting level 6
def deep_nesting(users):
    if users:                           # Level 1
        for user in users:              # Level 2
            if user.active:             # Level 3
                for order in user.orders:   # Level 4
                    if order.pending:       # Level 5
                        try:                # Level 6
                            process_order(order)
                        except Error:
                            continue

# HIGH: Very deep nesting level 7
def very_deep_nesting(config):
    if config:                          # Level 1
        if config.enabled:              # Level 2
            for section in config:      # Level 3
                if section.valid:       # Level 4
                    for item in section:    # Level 5
                        if item.active:     # Level 6
                            with open(item.file) as f:  # Level 7
                                process_file(f)

# OK: Low nesting with early returns
def good_function(data):
    if not data:
        return
    
    for item in data:
        if not item.valid:
            continue
        
        process(item)

# OK: Extracted helper functions
def well_refactored(users):
    if not users:
        return
    
    for user in users:
        process_user(user)

def process_user(user):
    if not user.active:
        return
    
    for order in user.orders:
        process_order(order)
'''

    print("Deep Nesting Detection Report")
    print("=" * 80)
    
    for issue in detect_deep_nesting(sample_code, "sample.py"):
        print(f"\nLine {issue.line}: {issue.function}")
        print(f"Severity: {issue.severity}")
        print(f"Message: {issue.message}")
        print(f"Recommendation: {issue.recommendation}")


