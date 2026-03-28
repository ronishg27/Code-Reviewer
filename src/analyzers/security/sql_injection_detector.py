import ast
from typing import Dict, Set, Optional

from src.analyzers.security.base import BaseDetector, Rule, Severity, run_detector
from src.models import Issue


class SQLInjectionDetector(BaseDetector):
    """Detector for SQL injection vulnerabilities."""
    
    DETECTOR_NAME = "SQL Injection Detector"
    DETECTOR_RULE = "Potential SQL Injection"
    
    SQL_SINK_METHODS: Set[str] = {
        "execute", "executemany", "executescript", "callproc",
        "execute_sql", "raw", "fetch", "fetchrow", "fetchval",
        "fetch_all", "fetch_one", "scalar", "scalars",
    }
    
    RULES: Dict[str, Rule] = {
        'fstring': Rule(
            severity=Severity.CRITICAL,
            message="SQL query uses f-string formatting",
            recommendation="Use parameterized queries with placeholders (?, %s, or named parameters)"
        ),
        'concat': Rule(
            severity=Severity.CRITICAL,
            message="SQL query uses string concatenation",
            recommendation="Use parameterized queries instead of string concatenation"
        ),
        'modulo': Rule(
            severity=Severity.CRITICAL,
            message="SQL query uses % string formatting",
            recommendation="Use parameterized queries with placeholders"
        ),
        'format': Rule(
            severity=Severity.CRITICAL,
            message="SQL query uses .format() method",
            recommendation="Use parameterized queries instead of .format()"
        ),

        'tainted_direct': Rule(
            severity= Severity.CRITICAL,
            message="SQL query is directly tainted by user input",
            recommendation="Use parameterized queries with placeholders "
        ),

        'tainted_propagated':Rule(
            severity=Severity.CRITICAL,
            message="SQL query uses variable containing user input",
            recommendation="Use parameterized queries. Avoid string concatenation or formatting with user input."
        )
    }
    
    SAFE_PARAM_KEYWORDS: Set[str] = {'params', 'parameters', 'args', 'bind'}
    
    def _on_call(self, node: ast.Call, func_name: str, resolved_name: str) -> None:
        """Check SQL method calls for injection vulnerabilities."""
        method_name = resolved_name.split('.')[-1]
            
        if method_name not in self.SQL_SINK_METHODS:
            return
        
        try: 
            
            if self._has_safe_parameters(node):
                return
            
            query_arg = self._get_query_argument(node)
            if not query_arg:
                return
            
            # Context-aware check: Does the query use tainted variables?
            tainted_vars = self.get_tainted_variables_in_expression(query_arg)

            if tainted_vars:
                # build detailed message
                taint_info  = tainted_vars[0]  # Get the first tainted variable for reporting

                if taint_info.data_flow:
                    # taint was propagated through multiple steps
                    flow_chain = " -> ".join(taint_info.data_flow + [taint_info.name])
                    additional = f"(tainted data flow: {flow_chain} from {taint_info.taint_source}) "
                    self.report_issue(node, self.RULES['tainted_propagated'], func_name, additional_message=additional)

                    
                else:
                    # direct use of taint variables
                    additional = f"(variable '{taint_info.name}' is tainted from {taint_info.taint_source}) "

                    self.report_issue(
                        node,
                        self.RULES['tainted_direct'],
                        func_name=func_name,
                        additional_message=additional,
                    )
                
                return
                
            # fallback to pattern-based detection
            self._check_query_vulnerability(node, query_arg, func_name)

        except Exception as e:
            import logging
            logging.warning(f"SQL detector error at line {node.lineno}: {e}")
            return
    
    def _get_query_argument(self, node: ast.Call) -> Optional[ast.AST]:
        """Extract the SQL query argument from a call."""
        if node.args:
            query_arg = node.args[0]
            if isinstance(query_arg, ast.Name):
                resolved = self.resolve_variable(query_arg.id)
                if resolved:
                    return resolved
            return query_arg
        
        for kw in node.keywords:
            if kw.arg in ('query', 'sql', 'statement'):
                return kw.value
        
        return None
    
    def _has_safe_parameters(self, node: ast.Call) -> bool:
        """Check if the call uses parameterized queries."""
        if len(node.args) > 1:
            return True
        
        return any(kw.arg in self.SAFE_PARAM_KEYWORDS for kw in node.keywords)


    def _check_query_vulnerability(
        self,
        node: ast.Call,
        query_arg: ast.AST,
        func_name: str
    ) -> None:
        """Check if a query argument is vulnerable."""
        rule_key = None
        
        if isinstance(query_arg, ast.JoinedStr):
            rule_key = 'fstring'
        elif isinstance(query_arg, ast.BinOp):
            if isinstance(query_arg.op, ast.Add):
                rule_key = 'concat'
            elif isinstance(query_arg.op, ast.Mod):
                rule_key = 'modulo'
        elif isinstance(query_arg, ast.Call):
            if isinstance(query_arg.func, ast.Attribute) and query_arg.func.attr == 'format':
                rule_key = 'format'
        
        if rule_key:
            self.report_issue(node, self.RULES[rule_key], func_name)


def detect_sql_injection(code: str, file_path: str = "UNKNOWN"):
    """Detect SQL injection vulnerabilities."""
    yield from run_detector(SQLInjectionDetector, code, file_path)