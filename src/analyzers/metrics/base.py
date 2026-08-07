import ast
from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class MetricLevel(Enum):
    """Levels at which metrics can be calculated."""
    FILE = "file"
    CLASS = "class"
    FUNCTION = "function"
    MODULE = "module"


@dataclass
class MetricResult:
    """Metric calculation result."""
    name: str
    value: float
    level: MetricLevel
    target: str  # Name of function/class/file
    line: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def rating(self) -> str:
        """Get a letter grade based on common thresholds."""
        return self.metadata.get('rating', 'N/A')


@dataclass
class CodeMetrics:
    """Collection of all metrics for a code entity."""
    target: str
    level: MetricLevel
    line: Optional[int] = None
    
    # Size metrics
    lines_of_code: int = 0
    logical_lines: int = 0
    comment_lines: int = 0
    blank_lines: int = 0
    
    # Complexity metrics
    cyclomatic_complexity: int = 0
    cognitive_complexity: int = 0
    
    # Maintainability
    maintainability_index: float = 0.0
    
    # Structure metrics
    nesting_depth: int = 0
    num_parameters: int = 0
    num_returns: int = 0
    
    # Class-specific
    num_methods: int = 0
    num_attributes: int = 0
    
    # Additional metrics
    custom_metrics: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            'target': self.target,
            'level': self.level.value,
            'line': self.line,
            'size': {
                'lines_of_code': self.lines_of_code,
                'logical_lines': self.logical_lines,
                'comment_lines': self.comment_lines,
                'blank_lines': self.blank_lines,
            },
            'complexity': {
                'cyclomatic': self.cyclomatic_complexity,
                'cognitive': self.cognitive_complexity,
            },
            'maintainability': {
                'index': self.maintainability_index,
            },
            'structure': {
                'nesting_depth': self.nesting_depth,
                'parameters': self.num_parameters,
                'returns': self.num_returns,
            },
            'custom': self.custom_metrics,
        }


class BaseMetricCalculator(ast.NodeVisitor, ABC):
    """Base class for metric calculators."""
    
    METRIC_NAME: str = "Base Metric"
    
    def __init__(self):
        self.results: List[MetricResult] = []
        self.current_class: Optional[str] = None
        self.current_function: Optional[str] = None
    
    @abstractmethod
    def calculate(self, tree: ast.AST, source_code: str = "") -> List[MetricResult]:
        """
        Calculate metrics for the given AST.
        
        Args:
            tree: AST to analyze
            source_code: Original source code (optional, for some metrics)
            
        Returns:
            List of metric results
        """
        pass
    
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Track class context."""
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track function context."""
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Track async function context."""
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function


def calculate_all_metrics(code: str) -> Dict[str, CodeMetrics]:
    """
    Calculate all available metrics for code.
    
    Args:
        code: Source code to analyze
        
    Returns:
        Dictionary mapping entity names to their metrics
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {}
    
    # Import calculators here to avoid circular imports
    from src.analyzers.metrics.complexity import ComplexityCalculator
    from src.analyzers.metrics.code_stats import CodeStatsCalculator
    from src.analyzers.metrics.maintainability import MaintainabilityCalculator
    
    calculators = [
        ComplexityCalculator(),
        CodeStatsCalculator(),
        MaintainabilityCalculator(),
    ]
    
    all_metrics: Dict[str, CodeMetrics] = {}
    
    for calculator in calculators:
        results = calculator.calculate(tree, code)
        
        for result in results:
            if result.target not in all_metrics:
                all_metrics[result.target] = CodeMetrics(
                    target=result.target,
                    level=result.level,
                    line=result.line
                )
            
            # Update the appropriate metric field
            metrics = all_metrics[result.target]
            _update_metrics(metrics, result)
    
    return all_metrics


def _update_metrics(metrics: CodeMetrics, result: MetricResult) -> None:
    """Update CodeMetrics object with a result."""
    # Map result names to metric fields
    mapping = {
        'cyclomatic_complexity': 'cyclomatic_complexity',
        'cognitive_complexity': 'cognitive_complexity',
        'lines_of_code': 'lines_of_code',
        'logical_lines': 'logical_lines',
        'comment_lines': 'comment_lines',
        'blank_lines': 'blank_lines',
        'maintainability_index': 'maintainability_index',
        'nesting_depth': 'nesting_depth',
        'num_parameters': 'num_parameters',
        'num_returns': 'num_returns',
    }
    
    if result.name in mapping:
        setattr(metrics, mapping[result.name], float(result.value))
    else:
        metrics.custom_metrics[result.name] = result.value