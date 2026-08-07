import ast
from typing import List, Optional

from src.analyzers.metrics.base import (
    BaseMetricCalculator,
    MetricResult,
    MetricLevel,
)


class CodeStatsCalculator(BaseMetricCalculator):
    """
    Calculate code statistics:
    - Lines of Code (LOC)
    - Logical Lines of Code (LLOC)
    - Comment Lines
    - Blank Lines
    - Number of parameters
    - Number of returns
    """
    
    METRIC_NAME = "Code Statistics"
    
    def calculate(self, tree: ast.AST, source_code: str = "") -> List[MetricResult]:
        """Calculate code statistics."""
        self.results = []
        self.source_lines = source_code.split('\n') if source_code else []
        self.visit(tree)
        return self.results
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Calculate stats for a function."""
        # Lines of code
        loc = self._count_loc(node)
        self.results.append(MetricResult(
            name="lines_of_code",
            value=loc,
            level=MetricLevel.FUNCTION,
            target=node.name,
            line=node.lineno,
            metadata={'rating': self._rate_loc(loc)}
        ))
        
        # Logical lines
        lloc = self._count_logical_lines(node)
        self.results.append(MetricResult(
            name="logical_lines",
            value=lloc,
            level=MetricLevel.FUNCTION,
            target=node.name,
            line=node.lineno,
            metadata={'rating': self._rate_lloc(lloc)}
        ))
        
        # Number of parameters
        num_params = len(node.args.args) + len(node.args.kwonlyargs)
        self.results.append(MetricResult(
            name="num_parameters",
            value=num_params,
            level=MetricLevel.FUNCTION,
            target=node.name,
            line=node.lineno,
            metadata={
                'rating': self._rate_parameters(num_params),
                'threshold_low': 3,
                'threshold_moderate': 5,
                'threshold_high': 7,
            }
        ))
        
        # Number of return statements
        num_returns = self._count_returns(node)
        self.results.append(MetricResult(
            name="num_returns",
            value=num_returns,
            level=MetricLevel.FUNCTION,
            target=node.name,
            line=node.lineno,
            metadata={
                'rating': self._rate_returns(num_returns),
                'threshold_low': 1,
                'threshold_moderate': 3,
                'threshold_high': 5,
            }
        ))
        
        # Continue visiting
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Calculate stats for async function."""
        self.visit_FunctionDef(node)
    
    def _count_loc(self, node: ast.FunctionDef) -> int:
        """Count physical lines of code."""
        if not node.body:
            return 0
        
        first_line = node.body[0].lineno
        
        # Skip docstring
        if (isinstance(node.body[0], ast.Expr) and
            isinstance(node.body[0].value, ast.Constant) and
            isinstance(node.body[0].value.value, str)):
            if len(node.body) > 1:
                first_line = node.body[1].lineno
            else:
                return 1
        
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
    
    def _count_logical_lines(self, node: ast.FunctionDef) -> int:
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
    
    def _count_returns(self, node: ast.FunctionDef) -> int:
        """Count return statements."""
        count = 0
        for child in ast.walk(node):
            if isinstance(child, ast.Return):
                count += 1
        return count
    
    def _rate_loc(self, loc: int) -> str:
        """Rate lines of code."""
        if loc <= 20:
            return "A (Concise)"
        elif loc <= 50:
            return "B (Reasonable)"
        elif loc <= 100:
            return "C (Long)"
        elif loc <= 200:
            return "D (Very Long)"
        else:
            return "F (Extremely Long)"
    
    def _rate_lloc(self, lloc: int) -> str:
        """Rate logical lines."""
        if lloc <= 15:
            return "A (Simple)"
        elif lloc <= 30:
            return "B (Moderate)"
        elif lloc <= 60:
            return "C (Complex)"
        else:
            return "F (Very Complex)"
    
    def _rate_parameters(self, num: int) -> str:
        """Rate number of parameters."""
        if num <= 3:
            return "A (Good)"
        elif num <= 5:
            return "B (Acceptable)"
        elif num <= 7:
            return "C (Many)"
        else:
            return "F (Too Many)"
    
    def _rate_returns(self, num: int) -> str:
        """Rate number of returns."""
        if num == 1:
            return "A (Single Exit)"
        elif num <= 3:
            return "B (Few Exits)"
        elif num <= 5:
            return "C (Multiple Exits)"
        else:
            return "F (Too Many Exits)"