import ast
import math
from typing import List

from src.analyzers.metrics.base import (
    BaseMetricCalculator,
    MetricResult,
    MetricLevel,
)


class MaintainabilityCalculator(BaseMetricCalculator):
    """
    Calculate Maintainability Index.
    
    MI = 171 - 5.2 * ln(Halstead Volume) - 0.23 * (Cyclomatic Complexity) - 16.2 * ln(Lines of Code)
    
    Scaled to 0-100 range.
    """
    
    METRIC_NAME = "Maintainability"
    
    def calculate(self, tree: ast.AST, source_code: str = "") -> List[MetricResult]:
        """Calculate maintainability index."""
        self.results = []
        self.visit(tree)
        return self.results
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Calculate maintainability for a function."""
        # Calculate components
        loc = self._count_loc(node)
        cyclomatic = self._calculate_cyclomatic(node)
        halstead_volume = self._calculate_halstead_volume(node)
        
        # Calculate Maintainability Index
        if loc > 0 and halstead_volume > 0:
            mi = (
                171 -
                5.2 * math.log(halstead_volume) -
                0.23 * cyclomatic -
                16.2 * math.log(loc)
            )
            
            # Normalize to 0-100 scale
            mi = max(0, min(100, mi * 100 / 171))
        else:
            mi = 100  # Empty function is perfectly maintainable :)
        
        self.results.append(MetricResult(
            name="maintainability_index",
            value=mi,
            level=MetricLevel.FUNCTION,
            target=node.name,
            line=node.lineno,
            metadata={
                'rating': self._rate_mi(mi),
                'components': {
                    'loc': loc,
                    'cyclomatic': cyclomatic,
                    'halstead_volume': halstead_volume,
                },
                'threshold_high': 85,
                'threshold_moderate': 65,
                'threshold_low': 45,
            }
        ))
        
        # Continue visiting
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Calculate maintainability for async function."""
        self.visit_FunctionDef(node)
    
    def _count_loc(self, node: ast.FunctionDef) -> int:
        """Count lines of code."""
        if not node.body:
            return 1
        
        first = node.body[0].lineno
        last = max(child.lineno for child in ast.walk(node) if hasattr(child, 'lineno'))
        return last - first + 1
    
    def _calculate_cyclomatic(self, node: ast.FunctionDef) -> int:
        """Calculate cyclomatic complexity."""
        complexity = 1
        
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        
        return complexity
    
    def _calculate_halstead_volume(self, node: ast.FunctionDef) -> float:
        """
        Calculate Halstead Volume.
        
        Volume = (n1 + n2) * log2(η1 + η2)
        
        Where:
        - n1 = total number of operators
        - n2 = total number of operands
        - η1 = number of distinct operators
        - η2 = number of distinct operands
        """
        operators = set()
        operands = set()
        operator_count = 0
        operand_count = 0
        
        for child in ast.walk(node):
            # Operators
            if isinstance(child, (ast.Add, ast.Sub, ast.Mult, ast.Div, ast.Mod,
                                ast.Pow, ast.LShift, ast.RShift, ast.BitOr,
                                ast.BitXor, ast.BitAnd, ast.FloorDiv)):
                operators.add(type(child).__name__)
                operator_count += 1
            
            elif isinstance(child, (ast.And, ast.Or)):
                operators.add(type(child).__name__)
                operator_count += 1
            
            elif isinstance(child, (ast.Eq, ast.NotEq, ast.Lt, ast.LtE,
                                  ast.Gt, ast.GtE, ast.Is, ast.IsNot,
                                  ast.In, ast.NotIn)):
                operators.add(type(child).__name__)
                operator_count += 1
            
            # Operands (variables and constants)
            elif isinstance(child, ast.Name):
                operands.add(child.id)
                operand_count += 1
            
            elif isinstance(child, ast.Constant):
                operands.add(str(child.value))
                operand_count += 1
        
        n1 = operator_count
        n2 = operand_count
        eta1 = len(operators)
        eta2 = len(operands)
        
        # Prevent division by zero and log(0)
        if eta1 + eta2 == 0 or n1 + n2 == 0:
            return 1.0  # ← Return 1 instead of 0 (better for MI calculation)
        
        try:
            volume = (n1 + n2) * math.log2(eta1 + eta2)
            return volume
        except (ValueError, ZeroDivisionError):
            return 1.0
    
    def _rate_mi(self, mi: float) -> str:
        """Rate maintainability index."""
        if mi >= 85:
            return "A (Highly Maintainable)"
        elif mi >= 65:
            return "B (Maintainable)"
        elif mi >= 45:
            return "C (Moderately Maintainable)"
        elif mi >= 25:
            return "D (Difficult to Maintain)"
        else:
            return "F (Very Difficult to Maintain)"