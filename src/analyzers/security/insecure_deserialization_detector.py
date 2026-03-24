import ast
from typing import Dict, Set

from src.analyzers.security.base import BaseDetector, Rule, Severity, run_detector
from src.models import Issue


class InsecureDeserializationDetector(BaseDetector):
    """Detector for insecure deserialization vulnerabilities."""
    
    DETECTOR_NAME = "Insecure Deserialization Detector"
    DETECTOR_RULE = "Insecure Deserialization"
    
    INSECURE_METHODS: Dict[str, Rule] = {
        'pickle.loads': Rule(
            severity=Severity.CRITICAL,
            message="pickle.loads() can execute arbitrary code during deserialization",
            recommendation="Use json.loads() or implement allowlist-based unpickling"
        ),
        'pickle.load': Rule(
            severity=Severity.CRITICAL,
            message="pickle.load() can execute arbitrary code during deserialization",
            recommendation="Use json.load() or implement allowlist-based unpickling"
        ),
        'pickle.Unpickler': Rule(
            severity=Severity.HIGH,
            message="pickle.Unpickler can execute arbitrary code if not properly restricted",
            recommendation="Override find_class() to implement allowlist of safe classes"
        ),
        'marshal.loads': Rule(
            severity=Severity.HIGH,
            message="marshal.loads() with untrusted data can cause crashes or code execution",
            recommendation="Avoid marshal for untrusted data; use json.loads() instead"
        ),
        'marshal.load': Rule(
            severity=Severity.HIGH,
            message="marshal.load() with untrusted data can cause crashes or code execution",
            recommendation="Avoid marshal for untrusted data; use json.load() instead"
        ),
        'yaml.unsafe_load': Rule(
            severity=Severity.CRITICAL,
            message="yaml.unsafe_load() explicitly allows arbitrary code execution",
            recommendation="Use yaml.safe_load() instead"
        ),
        'yaml.full_load': Rule(
            severity=Severity.MEDIUM,
            message="yaml.full_load() may allow some unsafe operations",
            recommendation="Use yaml.safe_load() for untrusted input"
        ),
        'jsonpickle.decode': Rule(
            severity=Severity.HIGH,
            message="jsonpickle.decode() can deserialize arbitrary Python objects",
            recommendation="Use json.loads() for untrusted data"
        ),
        'shelve.open': Rule(
            severity=Severity.HIGH,
            message="shelve uses pickle internally and is vulnerable to code execution",
            recommendation="Use a database or json-based storage for untrusted data"
        ),
        'dill.loads': Rule(
            severity=Severity.CRITICAL,
            message="dill.loads() can execute arbitrary code during deserialization",
            recommendation="Use json.loads() for untrusted data"
        ),
        'dill.load': Rule(
            severity=Severity.CRITICAL,
            message="dill.load() can execute arbitrary code during deserialization",
            recommendation="Use json.load() for untrusted data"
        ),
    }
    
    SAFE_YAML_LOADERS: Set[str] = {'SafeLoader', 'CSafeLoader', 'BaseLoader', 'CBaseLoader'}
    UNSAFE_YAML_LOADERS: Set[str] = {'FullLoader', 'UnsafeLoader', 'Loader', 'CLoader'}
    
    YAML_LOAD_RULE = Rule(
        severity=Severity.CRITICAL,
        message="yaml.load() without SafeLoader can execute arbitrary Python code",
        recommendation="Use yaml.safe_load() or yaml.load() with Loader=yaml.SafeLoader"
    )
    
    def _on_call(self, node: ast.Call, func_name: str, resolved_name: str) -> None:
        """Check for insecure deserialization."""
        try: 

            if resolved_name == 'yaml.load':
                self._check_yaml_load(node, func_name)
            elif resolved_name in self.INSECURE_METHODS:
                self.report_issue(node, self.INSECURE_METHODS[resolved_name], func_name)
        
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
    
    def _check_yaml_load(self, node: ast.Call, func_name: str) -> None:
        """Check yaml.load() for safe Loader usage."""
        loader_value = self.get_keyword_arg_value(node, 'Loader')
        
        if loader_value:
            loader_name = None
            if isinstance(loader_value, ast.Attribute):
                loader_name = loader_value.attr
            elif isinstance(loader_value, ast.Name):
                loader_name = loader_value.id
            
            if loader_name in self.SAFE_YAML_LOADERS:
                return
            
            if loader_name in self.UNSAFE_YAML_LOADERS:
                self.report_issue(
                    node, self.YAML_LOAD_RULE, func_name,
                    f"using unsafe Loader '{loader_name}'",
                    override_severity=Severity.HIGH
                )
                return
        
        self.report_issue(node, self.YAML_LOAD_RULE, func_name)


def detect_insecure_deserialization(code: str, file_path: str = "UNKNOWN"):
    """Detect insecure deserialization vulnerabilities."""
    yield from run_detector(InsecureDeserializationDetector, code, file_path)