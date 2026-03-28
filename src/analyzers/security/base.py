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


@dataclass 
class VariableContext:
    """
        Context information about a variable.
    
    Tracks:
    - Where it was defined
    - What type of value it holds
    - Whether it's tainted (user input, etc.)
    - Its data flow history
    """

    name: str
    definition_line: int
    value_node: Optional[ast.AST] = None
    is_tainted: bool = False
    taint_source: Optional[str] = None
    data_flow: List[str] = field(default_factory=list) #Tracks tranformations

    def __repr__(self):
        taint = f" [TAINTED from {self.taint_source}] " if self.is_tainted else ""
        flow = f" -> {' -> '.join(self.data_flow)}" if self.data_flow else ""
        return f"{self.name}@L{self.definition_line}{taint}{flow}"

class BaseDetector(ast.NodeVisitor, ABC):
    """
    Base class for all security vulnerability detectors.
    
    Provides common functionality for:
    - AST traversal
    - Import tracking and resolution
    - Context tracking (function/class scope)
    - Variable assignment tracking
    - Identifies tainted variables (user input, etc.)
    - Context-aware sink detection
    - Issue reporting
    """
    
    # Override in subclasses
    DETECTOR_NAME: str = "Base Detector"
    DETECTOR_RULE: str = "Generic Vulnerability"


    TAINT_SOURCES: Set[str]={
        # User input
        'input', 'raw_input',
        
        # Web frameworks
        'request.GET', 'request.POST', 'request.args', 'request.form',
        'request.values', 'request.cookies', 'request.headers',
        'request.data', 'request.json', 'request.body',
        
        # Environment
        'os.getenv', 'os.environ',
        
        # Files
        'open', 'read', 'readline', 'readlines',
        
        # Network
        'requests.get', 'requests.post', 'urllib.request.urlopen',
    }
    
    def __init__(self, file_path: str = "UNKNOWN"):
        self.file_path = file_path
        self.issues: List[Issue] = []
        self.imports: Dict[str, str] = {}  
        self.current_function: Optional[str] = None
        self.current_class: Optional[str] = None

        # context tracking for variables
        self.variable_contexts: Dict[str, VariableContext] = {}
        self.function_params: Dict[str, Set[str]] = {}

    
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
        
        # Track function parameters as potentiolly tainted
        param_names = set()
        for arg in node.args.args:
            param_names.add(arg.arg)
            # mark params as tainted (they come from outside)
            self.variable_contexts[arg.arg] =VariableContext(
                name=arg.arg,
                definition_line=node.lineno,
                is_tainted= True,
                taint_source="function_parameter"
                )
        
        self.function_params[node.name] = param_names

        self.generic_visit(node)
        self.current_function = old_function
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Track async function definitions."""
        old_function = self.current_function
        self.current_function = node.name

        param_names = set()
        for arg in node.args.args:
            param_names.add(arg.arg)
            # mark params as tainted (they come from outside)
            self.variable_contexts[arg.arg] =VariableContext(
                name=arg.arg,
                definition_line=node.lineno,
                is_tainted= True,
                taint_source="function_parameter"
                )
            
        self.function_params[node.name] = param_names
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
        # Check if the value being assigned is tainted
        is_tainted, taint_source = self._check_if_tainted(node.value)

        for target in node.targets:
            var_names = self._extract_var_names(target)

            for var_name in var_names:

                # check if RHS uses other variables 
                used_vars = self._extract_used_variables(node.value)
                data_flow=[]

                # if rhs uses tainted variables, propagate taint
                if not is_tainted:
                    for used_var in used_vars:
                        if used_var in self.variable_contexts:
                            ctx= self.variable_contexts[used_var]
                            if ctx.is_tainted:
                                is_tainted = True
                                taint_source = f"via {used_var} from {ctx.taint_source}"
                                data_flow  = ctx.data_flow + [used_var]
                                break
                
                self.variable_contexts[var_name]= VariableContext(
                    name=var_name, 
                    definition_line=node.lineno,
                    is_tainted=is_tainted,
                    taint_source=taint_source,
                    data_flow=data_flow,
                    value_node=node.value
                )
        
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
    
    # ==================== Context-Aware Utility Methods ====================
    
    def _check_if_tainted(self, node: ast.AST)-> tuple[bool, Optional[str]]:
        """
        Check if a value comes from a taint source.
        
        Returns:
            (is_tainted, taint_source)
            is_tainted: True if the value is tainted
            taint_source: Description of the taint source if tainted
        """

        if isinstance(node, ast.Call):
            func_name = get_function_name(node.func)
            if func_name:
                resolved = self.resolve_function_name(func_name)

                # check against know taint sources
                for taint_src in self.TAINT_SOURCES:
                    if resolved == taint_src or resolved.endswith(f".{taint_src}"):
                        return True, taint_src

                # also check for attribute calls (e.g. request.GET['key'])
                if isinstance(node.func, ast.Attribute):
                    full_attr = self._get_full_attribute_name(node.func)
                    for taint_source in self.TAINT_SOURCES:
                        if full_attr and taint_source in full_attr:
                            return True, full_attr
        elif isinstance(node, ast.Subscript):
            value_name = self._get_full_attribute_name(node.value)
            if value_name:
                for taint_source in self.TAINT_SOURCES:
                    if taint_source in value_name:
                        return True, value_name
                    
        return False, None
    
    def _get_full_attribute_name(self, node: ast.AST) -> Optional[str]:
        """Get full attribute name like 'request.GET'."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            base = self._get_full_attribute_name(node.value)
            if base:
                return f"{base}.{node.attr}"
            return node.attr
        return None

    def _extract_var_names(self, node:ast.AST)-> List[str]:
        """Extract Variable names from an assignment target."""
        names = []
        if isinstance(node, ast.Name):
            names.append(node.id)
        elif isinstance(node, (ast.Tuple, ast.List)):
            for elt in node.elts:
                names.extend(self._extract_var_names(elt))

        elif isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Name):
                names.append(node.value.id)
        
        return names
    

    def _extract_used_variables(self, node: ast.AST) -> Set[str]:
        """Extract all variable names used in an expression."""
        used = set()
    
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                used.add(child.id)
        
        return used
    
    def is_variable_tainted(self, var_name:str) -> bool:
        """Check if a variable is tainted based on context."""
        ctx = self.variable_contexts.get(var_name)
        return ctx.is_tainted if ctx else False
    
    def get_variable_context(self, var_name: str)-> Optional[VariableContext]:
        """Get the context of a variable."""
        return self.variable_contexts.get(var_name)
    
    def get_tainted_variables_in_expression(self, node:ast.AST) -> List[VariableContext]:
        "Get All tainted varibales used in an expression."
        tainted= []
        used_vars = self._extract_used_variables(node)

        for var_name in used_vars:
            if var_name in self.variable_contexts:
                ctx = self.variable_contexts[var_name]
                if ctx.is_tainted:
                    tainted.append(ctx)
        return tainted

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
    
    def resolve_variable(self, name:ast.AST) -> Optional[ast.AST]:
        """Resolve a variable name to its assigned value.         """

        if name in self.variable_contexts:
            return self.variable_contexts[name].value_node
        
        return None
        
        # """
        # Resolve a variable name to its assigned value.
        
        # Args:
        #     name: Variable name to resolve
        #     max_depth: Maximum recursion depth
        #     _seen: Set of already seen variables (prevents cycles)
        
        # Returns:
        #     AST node of the resolved value, or None
        # """
        # if _seen is None:
        #     _seen = set()
        
        # # Prevent infinite recursion
        # if name in _seen or len(_seen) >= max_depth:
        #     return None
        
        # _seen.add(name)
        
        # value = self.variable_assignments.get(name)
        # if value is None:
        #     return None
        
        # # If value is another variable, resolve it
        # if isinstance(value, ast.Name):
        #     return self.resolve_variable(value.id, max_depth, _seen)
        
        # return value
    
    # def is_tainted(self, name: str) -> bool:
    #     """Check if a variable is potentially tainted."""
    #     return name in self.tainted_variables
    
    # def _is_tainted_value(self, node: ast.AST) -> bool:
    #     """Check if a value comes from a tainted source."""
    #     if isinstance(node, ast.Call):
    #         func_name = get_function_name(node.func)
    #         if func_name:
    #             tainted_sources = {
    #                 'input', 'raw_input',
    #                 'sys.stdin.read', 'sys.stdin.readline',
    #                 'request.args.get', 'request.form.get',
    #                 'request.GET.get', 'request.POST.get',
    #                 'os.environ.get', 'os.getenv'
    #             }
    #             return any(func_name.endswith(src) for src in tainted_sources)
    #     return False
    
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