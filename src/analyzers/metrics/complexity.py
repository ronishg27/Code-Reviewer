import ast
from typing import List, Optional

from src.analyzers.metrics.base import (
    BaseMetricCalculator,
    MetricResult,
    MetricLevel,
)


class ComplexityCalculator(BaseMetricCalculator):
    """
    Calculate complexity metrics:
    - Cyclomatic Complexity (McCabe)
    - Cognitive Complexity
    - Nesting Depth
    """
    
    METRIC_NAME = "Complexity"
    
    def calculate(self, tree: ast.AST, source_code: str = "") -> List[MetricResult]:
        """Calculate all complexity metrics."""
        self.results = []
        self.visit(tree)
        return self.results
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Calculate complexity for a function."""
        # Cyclomatic Complexity
        cyclomatic = self._calculate_cyclomatic(node)
        self.results.append(MetricResult(
            name="cyclomatic_complexity",
            value=cyclomatic,
            level=MetricLevel.FUNCTION,
            target=node.name,
            line=node.lineno,
            metadata={
                'rating': self._rate_cyclomatic(cyclomatic),
                'threshold_low': 10,
                'threshold_moderate': 20,
                'threshold_high': 50,
            }
        ))
        
        # Cognitive Complexity
        cognitive = self._calculate_cognitive(node)
        self.results.append(MetricResult(
            name="cognitive_complexity",
            value=cognitive,
            level=MetricLevel.FUNCTION,
            target=node.name,
            line=node.lineno,
            metadata={
                'rating': self._rate_cognitive(cognitive),
                'threshold_low': 15,
                'threshold_moderate': 25,
                'threshold_high': 50,
            }
        ))
        
        # Nesting Depth
        nesting = self._calculate_nesting_depth(node)
        self.results.append(MetricResult(
            name="nesting_depth",
            value=nesting,
            level=MetricLevel.FUNCTION,
            target=node.name,
            line=node.lineno,
            metadata={
                'rating': self._rate_nesting(nesting),
                'threshold_low': 3,
                'threshold_moderate': 5,
                'threshold_high': 7,
            }
        ))
        
        # Continue visiting
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Calculate complexity for async function."""
        self.visit_FunctionDef(node)
    
    def _calculate_cyclomatic(self, node: ast.FunctionDef) -> int:
        """
        Calculate Cyclomatic Complexity (McCabe).
        
        CC = Number of decision points + 1
        Decision points: if, for, while, and, or, except, with
        """
        complexity = 1  # Base complexity
        
        for child in ast.walk(node):
            # Decision points
            if isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                complexity += 1
            
            # Exception handlers
            elif isinstance(child, ast.ExceptHandler):
                complexity += 1
            
            # Boolean operators in conditions
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
            
            # Comprehensions
            elif isinstance(child, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                for generator in child.generators:
                    complexity += 1
                    for if_ in generator.ifs:
                        complexity += 1
        
        return complexity
    
    def _calculate_cognitive(self, node: ast.FunctionDef) -> int:
        """
        Calculate Cognitive Complexity.
        
        More sophisticated than cyclomatic - accounts for nesting
        and ignores certain structures.
        """
        complexity = 0
        nesting_level = 0
        
        def visit_node(n: ast.AST, level: int) -> int:
            nonlocal complexity
            score = 0
            
            # Increment for control flow
            if isinstance(n, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                score = 1 + level
                complexity += score
                
                # Visit body with increased nesting
                for child in ast.iter_child_nodes(n):
                    visit_node(child, level + 1)
                
                return score
            
            # Boolean operators add to cognitive load
            elif isinstance(n, ast.BoolOp):
                complexity += 1
            
            # Exception handlers
            elif isinstance(n, ast.ExceptHandler):
                complexity += 1 + level
            
            # Recursion adds cognitive load
            elif isinstance(n, ast.Call):
                if isinstance(n.func, ast.Name):
                    if n.func.id == node.name:
                        complexity += 1
            
            # Continue visiting children at same level
            for child in ast.iter_child_nodes(n):
                if not isinstance(child, (ast.If, ast.While, ast.For, ast.AsyncFor)):
                    visit_node(child, level)
            
            return 0
        
        visit_node(node, 0)
        return complexity
    
    def _calculate_nesting_depth(self, node: ast.FunctionDef) -> int:
        """Calculate maximum nesting depth."""
        max_depth = 0
        
        def visit_node(n: ast.AST, depth: int) -> int:
            nonlocal max_depth
            max_depth = max(max_depth, depth)
            
            if isinstance(n, (ast.If, ast.For, ast.While, ast.Try, 
                            ast.With, ast.AsyncFor, ast.AsyncWith)):
                for child in ast.iter_child_nodes(n):
                    visit_node(child, depth + 1)
            else:
                for child in ast.iter_child_nodes(n):
                    visit_node(child, depth)
        
        for stmt in node.body:
            visit_node(stmt, 1)
        
        return max_depth
    
    def _rate_cyclomatic(self, cc: int) -> str:
        """Rate cyclomatic complexity."""
        if cc <= 5:
            return "A (Simple)"
        elif cc <= 10:
            return "B (Moderate)"
        elif cc <= 20:
            return "C (Complex)"
        elif cc <= 50:
            return "D (Very Complex)"
        else:
            return "F (Extremely Complex)"
    
    def _rate_cognitive(self, cog: int) -> str:
        """Rate cognitive complexity."""
        if cog <= 5:
            return "A (Simple)"
        elif cog <= 15:
            return "B (Moderate)"
        elif cog <= 25:
            return "C (Complex)"
        elif cog <= 50:
            return "D (Very Complex)"
        else:
            return "F (Extremely Complex)"
    
    def _rate_nesting(self, depth: int) -> str:
        """Rate nesting depth."""
        if depth <= 2:
            return "A (Flat)"
        elif depth <= 4:
            return "B (Acceptable)"
        elif depth <= 6:
            return "C (Deep)"
        else:
            return "F (Very Deep)"