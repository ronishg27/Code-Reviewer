import ast
from abc import ABC, abstractmethod
from typing import Generator, Dict, Set, Optional, List, Any
from dataclasses import dataclass, field
from enum import Enum

from src.models import make_issue, Issue
from src.utils import get_function_name


class Severity(Enum):
    """Severity levels for vulnerabilities."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Rule:
    """Base rule definition for vulnerability checks."""
    severity: Severity
    message: str
    recommendation: str
    category: str = "SECURITY"
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseDetector(ast.NodeVisitor, ABC):
    """
    Base class for all security vulnerability detectors.
    
    Provides common functionality for:
    - AST traversal
    - Import tracking and resolution
    - Context tracking (function/class scope)
    - Variable assignment tracking
    - Taint analysis
    - Issue reporting
    """
    
    # Override in subclasses
    DETECTOR_NAME: str = "Base Detector"
    DETECTOR_RULE: str = "Generic Vulnerability"
    
    def __init__(self, file_path: str = "UNKNOWN"):
        self.file_path = file_path
        self.issues: List[Issue] = []
        self.imports: Dict[str, str] = {}  # alias -> full_module_path
        self.current_function: Optional[str] = None
        self.current_class: Optional[str] = None
        self.variable_assignments: Dict[str, ast.AST] = {}
        self.tainted_variables: Set[str] = set()
    
    # ==================== Import Tracking ====================
    
    def visit_Import(self, node: ast.Import) -> None:
        """Track import statements."""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.imports[name] = alias.name
            self._on_import(node, alias.name, name)
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Track from...import statements."""
        if node.module:
            for alias in node.names:
                name = alias.asname if alias.asname else alias.name
                full_name = f"{node.module}.{alias.name}"
                self.imports[name] = full_name
                self._on_import_from(node, node.module, alias.name, name)
        self.generic_visit(node)
    
    def _on_import(self, node: ast.Import, module: str, alias: str) -> None:
        """Hook for subclasses to handle import statements."""
        pass
    
    def _on_import_from(self, node: ast.ImportFrom, module: str, name: str, alias: str) -> None:
        """Hook for subclasses to handle from...import statements."""
        pass
    
    # ==================== Context Tracking ====================
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Track function definitions."""
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Track async function definitions."""
        old_function = self.current_function
        self.current_function = node.name
        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Track class definitions."""
        old_class = self.current_class
        self.current_class = node.name
        self.generic_visit(node)
        self.current_class = old_class
    
    def visit_Assign(self, node: ast.Assign) -> None:
        """Track variable assignments."""
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.variable_assignments[target.id] = node.value
                if self._is_tainted_value(node.value):
                    self.tainted_variables.add(target.id)
        
        self._on_assign(node)
        self.generic_visit(node)
    
    def _on_assign(self, node: ast.Assign) -> None:
        """Hook for subclasses to handle assignments."""
        pass
    
    # ==================== Call Analysis ====================
    
    def visit_Call(self, node: ast.Call) -> None:
        """Analyze function calls."""
        func_name = get_function_name(node.func)
        
        if func_name:
            resolved_name = self.resolve_function_name(func_name)
            self._on_call(node, func_name, resolved_name)
        
        self.generic_visit(node)
    
    @abstractmethod
    def _on_call(self, node: ast.Call, func_name: str, resolved_name: str) -> None:
        """
        Handle function calls - must be implemented by subclasses.
        
        Args:
            node: The AST Call node
            func_name: The function name as written in code
            resolved_name: The fully resolved function name
        """
        pass
    
    # ==================== Utility Methods ====================
    
    def resolve_function_name(self, func_name: str) -> str:
        """Resolve aliased import names to actual module.function."""
        parts = func_name.split('.')
        if parts[0] in self.imports:
            actual_module = self.imports[parts[0]]
            if len(parts) > 1:
                return f"{actual_module}.{'.'.join(parts[1:])}"
            return actual_module
        return func_name
    
    def resolve_variable(self, name: str, max_depth: int = 5, _seen: Optional[set] = None) -> Optional[ast.AST]:
        """
        Resolve a variable name to its assigned value.
        
        Args:
            name: Variable name to resolve
            max_depth: Maximum recursion depth
            _seen: Set of already seen variables (prevents cycles)
        
        Returns:
            AST node of the resolved value, or None
        """
        if _seen is None:
            _seen = set()
        
        # Prevent infinite recursion
        if name in _seen or len(_seen) >= max_depth:
            return None
        
        _seen.add(name)
        
        value = self.variable_assignments.get(name)
        if value is None:
            return None
        
        # If value is another variable, resolve it
        if isinstance(value, ast.Name):
            return self.resolve_variable(value.id, max_depth, _seen)
        
        return value
    
    def is_tainted(self, name: str) -> bool:
        """Check if a variable is potentially tainted."""
        return name in self.tainted_variables
    
    def _is_tainted_value(self, node: ast.AST) -> bool:
        """Check if a value comes from a tainted source."""
        if isinstance(node, ast.Call):
            func_name = get_function_name(node.func)
            if func_name:
                tainted_sources = {
                    'input', 'raw_input',
                    'sys.stdin.read', 'sys.stdin.readline',
                    'request.args.get', 'request.form.get',
                    'request.GET.get', 'request.POST.get',
                    'os.environ.get', 'os.getenv'
                }
                return any(func_name.endswith(src) for src in tainted_sources)
        return False
    
    def is_dynamic_value(self, node: ast.AST) -> bool:
        """Check if a node represents a dynamic/computed value."""
        if isinstance(node, (ast.BinOp, ast.JoinedStr, ast.Call)):
            return True
        if isinstance(node, ast.Name):
            return True  # Variables are potentially dynamic
        if isinstance(node, ast.Subscript):
            return True
        if isinstance(node, ast.List):
            return any(self.is_dynamic_value(el) for el in node.elts)
        return False
    
    def has_keyword_arg(
        self,
        node: ast.Call,
        arg_name: str,
        expected_value: Any = None
    ) -> bool:
        """Check if a call has a specific keyword argument."""
        for keyword in node.keywords:
            if keyword.arg == arg_name:
                if expected_value is None:
                    return True
                if isinstance(keyword.value, ast.Constant):
                    return keyword.value.value == expected_value
        return False
    
    def get_keyword_arg_value(self, node: ast.Call, arg_name: str) -> Optional[ast.AST]:
        """Get the value of a keyword argument."""
        for keyword in node.keywords:
            if keyword.arg == arg_name:
                return keyword.value
        return None
    
    def get_context_string(self) -> str:
        """Get a string describing the current context."""
        parts = []
        if self.current_function:
            parts.append(f"function '{self.current_function}'")
        if self.current_class:
            parts.append(f"class '{self.current_class}'")
        return f" (in {', '.join(parts)})" if parts else ""
    
    # ==================== Issue Reporting ====================
    
    def report_issue(
        self,
        node: ast.AST,
        rule: Rule,
        func_name: str,
        additional_message: str = "",
        override_severity: Optional[Severity] = None
    ) -> None:
        """Report a vulnerability issue."""
        severity = override_severity or rule.severity
        message = rule.message
        if additional_message:
            message = f"{message} {additional_message}"
        
        self.issues.append(
            make_issue(
                filename=self.file_path,
                line=node.lineno,
                rule=self.DETECTOR_RULE,
                function=func_name,
                severity=severity.value,
                message=message,
                recommendation=rule.recommendation,
                category=rule.category
            )
        )


def run_detector( 
    detector_class: type,
    code: str,
    file_path: str = "UNKNOWN"
) -> Generator[Issue, None, None]:
    """
    Run a detector on the given code.
    
    Args:
        detector_class: The detector class to use
        code: The source code to analyze
        file_path: The path of the file being analyzed
        
    Yields:
        Issue objects for each detected vulnerability
    """
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
    
    # Add parent references for context
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent
    
    detector = detector_class(file_path)
    detector.visit(tree)
    
    yield from detector.issues