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
            recommendation="Use subprocess.run() with a list of arguments and shell=False"
        ),
        'os.popen': Rule(
            severity=Severity.CRITICAL,
            message="os.popen() executes commands through the shell",
            recommendation="Use subprocess.run() with a list of arguments and shell=False"
        ),
        'os.popen2': Rule(
            severity=Severity.CRITICAL,
            message="os.popen2() executes commands through the shell",
            recommendation="Use subprocess.run() with a list of arguments and shell=False"
        ),
        'os.popen3': Rule(
            severity=Severity.CRITICAL,
            message="os.popen3() executes commands through the shell",
            recommendation="Use subprocess.run() with a list of arguments and shell=False"
        ),
        'os.popen4': Rule(
            severity=Severity.CRITICAL,
            message="os.popen4() executes commands through the shell",
            recommendation="Use subprocess.run() with a list of arguments and shell=False"
        ),
        'subprocess.call': Rule(
            severity=Severity.HIGH,
            message="subprocess.call() can be vulnerable with shell=True or dynamic input",
            recommendation="Use subprocess.run() with a list of arguments and shell=False",
            metadata={'requires_shell': True}
        ),
        'subprocess.run': Rule(
            severity=Severity.MEDIUM,
            message="subprocess.run() can be vulnerable with shell=True or string arguments",
            recommendation="Use a list of arguments and ensure shell=False",
            metadata={'requires_shell': True}
        ),
        'subprocess.Popen': Rule(
            severity=Severity.MEDIUM,
            message="subprocess.Popen() can be vulnerable with shell=True",
            recommendation="Use a list of arguments and ensure shell=False",
            metadata={'requires_shell': True}
        ),
        'subprocess.check_call': Rule(
            severity=Severity.HIGH,
            message="subprocess.check_call() can be vulnerable with shell=True",
            recommendation="Use subprocess.run() with a list of arguments and shell=False",
            metadata={'requires_shell': True}
        ),
        'subprocess.check_output': Rule(
            severity=Severity.HIGH,
            message="subprocess.check_output() can be vulnerable with shell=True",
            recommendation="Use subprocess.run() with capture_output=True and shell=False",
            metadata={'requires_shell': True}
        ),
        'subprocess.getoutput': Rule(
            severity=Severity.CRITICAL,
            message="subprocess.getoutput() always uses shell=True",
            recommendation="Use subprocess.run() with a list of arguments and shell=False"
        ),
        'subprocess.getstatusoutput': Rule(
            severity=Severity.CRITICAL,
            message="subprocess.getstatusoutput() always uses shell=True",
            recommendation="Use subprocess.run() with a list of arguments and shell=False"
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
            is_dynamic = self._check_dynamic_input(node)
            requires_shell = rule.metadata.get('requires_shell', False)
            
            is_vulnerable = False
            severity = rule.severity
            context_parts = []
            
            if resolved_name in self.ALWAYS_DANGEROUS:
                is_vulnerable = True
                if is_dynamic:
                    context_parts.append("with dynamic input")
            elif has_shell:
                is_vulnerable = True
                severity = Severity.CRITICAL
                context_parts.append("with shell=True")
            elif is_dynamic and not requires_shell:
                is_vulnerable = True
                context_parts.append("with dynamic input")
            
            if is_vulnerable:
                additional = f"({', '.join(context_parts)})" if context_parts else ""
                self.report_issue(node, rule, func_name, additional, severity)
            
        except (AttributeError, KeyError, IndexError, TypeError, ValueError) as e:
            # Log error but don't crash
            import warnings
            warnings.warn(
                f"{self.DETECTOR_NAME} error at line {getattr(node, 'lineno', '?')}: {e}",
                RuntimeWarning
            )
            return
        except Exception as e:
            # Catch-all for unexpected errors
            import warnings
            warnings.warn(
                f"{self.DETECTOR_NAME} unexpected error: {e}",
                RuntimeWarning
            )
            return
    
    def _check_dynamic_input(self, node: ast.Call) -> bool:
        """Check if the call has dynamic input."""
        if not node.args:
            return False
        return self.is_dynamic_value(node.args[0])


def detect_command_injection(code: str, file_path: str = "UNKNOWN"):
    """Detect command injection vulnerabilities."""
    yield from run_detector(CommandInjectionDetector, code, file_path)