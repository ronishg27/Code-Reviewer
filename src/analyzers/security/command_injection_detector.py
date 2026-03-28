import ast
from typing import Dict, Set

from src.analyzers.security.base import BaseDetector, Rule, Severity, run_detector
from src.models import Issue


class CommandInjectionDetector(BaseDetector):
    """Detector for command injection vulnerabilities."""
    
    DETECTOR_NAME = "Command Injection Detector"
    DETECTOR_RULE = "Command Injection"
    
    DANGEROUS_FUNCTIONS: Dict[str, Rule] = {
        'os.system': Rule(
            severity=Severity.CRITICAL,
            message="os.system() executes commands through the shell",
            recommendation="Use subprocess.run([...], shell=False) with a list of arguments"
        ),
        'os.popen': Rule(
            severity=Severity.CRITICAL,
            message="os.popen() executes commands through the shell",
            recommendation="Use subprocess.run([...], shell=False) with a list of arguments"
        ),
        'os.popen2': Rule(
            severity=Severity.CRITICAL,
            message="os.popen2() executes commands through the shell",
            recommendation="Use subprocess.run([...], shell=False) with a list of arguments"
        ),
        'os.popen3': Rule(
            severity=Severity.CRITICAL,
            message="os.popen3() executes commands through the shell",
            recommendation="Use subprocess.run([...], shell=False) with a list of arguments"
        ),
        'os.popen4': Rule(
            severity=Severity.CRITICAL,
            message="os.popen4() executes commands through the shell",
            recommendation="Use subprocess.run([...], shell=False) with a list of arguments"
        ),
        'subprocess.call': Rule(
            severity=Severity.HIGH,
            message="subprocess.call() can be vulnerable with shell=True or dynamic input",
            recommendation="Use subprocess.run([...], shell=False) with a list of arguments",
            metadata={'requires_shell': True}
        ),
        'subprocess.run': Rule(
            severity=Severity.MEDIUM,
            message="subprocess.run() can be vulnerable with shell=True or string arguments",
            recommendation="Use subprocess.run([...], shell=False) with a list of arguments",
            metadata={'requires_shell': True}
        ),
        'subprocess.Popen': Rule(
            severity=Severity.MEDIUM,
            message="subprocess.Popen() can be vulnerable with shell=True",
            recommendation="Use subprocess.run([...], shell=False) with a list of arguments",
            metadata={'requires_shell': True}
        ),
        'subprocess.check_call': Rule(
            severity=Severity.HIGH,
            message="subprocess.check_call() can be vulnerable with shell=True",
            recommendation="Use subprocess.run([...], shell=False) with a list of arguments",
            metadata={'requires_shell': True}
        ),
        'subprocess.check_output': Rule(
            severity=Severity.HIGH,
            message="subprocess.check_output() can be vulnerable with shell=True",
            recommendation="Use subprocess.run([...], capture_output=True, shell=False)",
            metadata={'requires_shell': True}
        ),
        'subprocess.getoutput': Rule(
            severity=Severity.CRITICAL,
            message="subprocess.getoutput() always uses shell=True",
            recommendation="Use subprocess.run([...], shell=False) with a list of arguments"
        ),
        'subprocess.getstatusoutput': Rule(
            severity=Severity.CRITICAL,
            message="subprocess.getstatusoutput() always uses shell=True",
            recommendation="Use subprocess.run([...], shell=False) with a list of arguments "
        ),
        'eval': Rule(
            severity=Severity.CRITICAL,
            message="eval() executes arbitrary Python code",
            recommendation="Use ast.literal_eval() for safe literal evaluation"
        ),
        'exec': Rule(
            severity=Severity.CRITICAL,
            message="exec() executes arbitrary Python code",
            recommendation="Avoid exec; refactor to use safer alternatives"
        ),
        'compile': Rule(
            severity=Severity.HIGH,
            message="compile() can execute arbitrary code with eval/exec",
            recommendation="Avoid compiling untrusted code"
        ),
        '__import__': Rule(
            severity=Severity.HIGH,
            message="__import__() with user input can load arbitrary modules",
            recommendation="Use importlib with strict allowlisting"
        ),
    }
    
    ALWAYS_DANGEROUS: Set[str] = {
        'eval', 'exec', 'compile', '__import__',
        'os.system', 'os.popen', 'os.popen2', 'os.popen3', 'os.popen4',
        'subprocess.getoutput', 'subprocess.getstatusoutput'
    }
    
    def _on_call(self, node: ast.Call, func_name: str, resolved_name: str) -> None:
        """Check for command injection vulnerabilities."""
        try:
            if resolved_name not in self.DANGEROUS_FUNCTIONS:
                return
            
            rule = self.DANGEROUS_FUNCTIONS[resolved_name]
            has_shell = self.has_keyword_arg(node, 'shell', True)
            requires_shell = rule.metadata.get('requires_shell', False)
            
            # step 1: taint analysis
            taint_info=None
            if node.args:
                tainted = self.get_tainted_variables_in_expression(node.args[0])
                if tainted:
                    taint_info= tainted[0]

            if taint_info:
                if taint_info.data_flow:
                    flow = " -> ".join(taint_info.data_flow+ [taint_info.name])
                    additional = f"(tainted data flow: '{flow}' from: {taint_info.taint_source})"
                else:
                    additional = f"(tainted variable: '{taint_info.name}' from: {taint_info.taint_source})"

                self.report_issue(node, rule, func_name, additional, Severity.CRITICAL)
                return
            
            # step 2: dangerous function analysis



            if resolved_name in self.ALWAYS_DANGEROUS:
                self.report_issue(node, rule, func_name, "", rule.severity)
                return
            
            # step 3: shell=True analysis
            if has_shell:
                self.report_issue(node, rule, func_name, "with shell=True", Severity.CRITICAL)
                return
            


            # step 4; heuristic dynamic input analysis
            is_dynamic= self._check_dynamic_input(node)


            if is_dynamic:
                severity = Severity.HIGH if requires_shell else Severity.MEDIUM
                self.report_issue(
                    node, rule, func_name, "with dynamic input", severity
                )
            return
        
        except Exception as e:
            import logging
            logging.warning(f"Command injection detector error at line {node.lineno}: {e}")
            return
    
    def _check_dynamic_input(self, node: ast.Call) -> bool:
        """Check if the call has dynamic input."""
        if not node.args:
            return False
        return self.is_dynamic_value(node.args[0])


def detect_command_injection(code: str, file_path: str = "UNKNOWN"):
    """Detect command injection vulnerabilities."""
    yield from run_detector(CommandInjectionDetector, code, file_path)