import ast
from typing import Dict, Set

from src.analyzers.security.base import BaseDetector, Rule, Severity, run_detector
from src.models import Issue


class WeakRandomDetector(BaseDetector):
    """Detector for weak random number generation vulnerabilities."""
    
    DETECTOR_NAME = "Weak Random Detector"
    DETECTOR_RULE = "Weak Random Number Generation"
    
    WEAK_RANDOM_FUNCTIONS: Dict[str, Rule] = {
        'random.random': Rule(
            severity=Severity.HIGH,
            message="random.random() uses a weak PRNG not suitable for security",
            recommendation="Use secrets.SystemRandom().random() for cryptographic operations"
        ),
        'random.randint': Rule(
            severity=Severity.HIGH,
            message="random.randint() is not cryptographically secure",
            recommendation="Use secrets.randbelow() or secrets.SystemRandom().randint()"
        ),
        'random.randrange': Rule(
            severity=Severity.HIGH,
            message="random.randrange() is not cryptographically secure",
            recommendation="Use secrets.randbelow() or secrets.SystemRandom().randrange()"
        ),
        'random.choice': Rule(
            severity=Severity.HIGH,
            message="random.choice() is not cryptographically secure",
            recommendation="Use secrets.choice() for security-sensitive selections"
        ),
        'random.choices': Rule(
            severity=Severity.HIGH,
            message="random.choices() is not cryptographically secure",
            recommendation="Use [secrets.choice(seq) for _ in range(k)]"
        ),
        'random.shuffle': Rule(
            severity=Severity.HIGH,
            message="random.shuffle() is not cryptographically secure",
            recommendation="Use secrets.SystemRandom().shuffle()"
        ),
        'random.sample': Rule(
            severity=Severity.HIGH,
            message="random.sample() is not cryptographically secure",
            recommendation="Use secrets.SystemRandom().sample()"
        ),
        'random.uniform': Rule(
            severity=Severity.MEDIUM,
            message="random.uniform() is not cryptographically secure",
            recommendation="Use secrets.SystemRandom().uniform()"
        ),
        'random.getrandbits': Rule(
            severity=Severity.HIGH,
            message="random.getrandbits() is not cryptographically secure",
            recommendation="Use secrets.randbits()"
        ),
        'random.seed': Rule(
            severity=Severity.CRITICAL,
            message="Explicitly seeding random makes it predictable",
            recommendation="Never seed random for security; use secrets module"
        ),
        'random.Random': Rule(
            severity=Severity.HIGH,
            message="random.Random() creates a weak PRNG instance",
            recommendation="Use secrets.SystemRandom()"
        ),
    }
    
    SECURITY_CONTEXTS: Set[str] = {
        'token', 'secret', 'key', 'password', 'salt', 'nonce', 'iv',
        'session', 'csrf', 'auth', 'crypto', 'otp', 'api_key',
        'access_token', 'refresh_token', 'private', 'secure'
    }
    
    RANDOM_IMPORT_RULE = Rule(
        severity=Severity.INFO,
        message="'random' module imported - ensure not used for security",
        recommendation="Use 'secrets' module for cryptographic randomness"
    )
    
    def _on_import(self, node: ast.Import, module: str, alias: str) -> None:
        """Warn about random module imports."""
        if module == 'random':
            self.report_issue(node, self.RANDOM_IMPORT_RULE, module)
    
    def _on_import_from(self, node: ast.ImportFrom, module: str, name: str, alias: str) -> None:
        """Warn about importing from random module."""
        if module == 'random':
            self.report_issue(node, self.RANDOM_IMPORT_RULE, f"random.{name}")
    
    def _on_call(self, node: ast.Call, func_name: str, resolved_name: str) -> None:
        """Check for weak random usage."""
        try:
            if resolved_name not in self.WEAK_RANDOM_FUNCTIONS:
                return
            
            rule = self.WEAK_RANDOM_FUNCTIONS[resolved_name]
            severity = rule.severity
            
            # Escalate severity in security context
            if self._is_security_context():
                if severity == Severity.HIGH:
                    severity = Severity.CRITICAL
                elif severity == Severity.MEDIUM:
                    severity = Severity.HIGH
            
            context = self.get_context_string()
            self.report_issue(node, rule, func_name, context, severity)

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
    
    def _is_security_context(self) -> bool:
        """Check if current context is security-related."""
        if self.current_function:
            func_lower = self.current_function.lower()
            if any(kw in func_lower for kw in self.SECURITY_CONTEXTS):
                return True
        
        if self.current_class:
            class_lower = self.current_class.lower()
            if any(kw in class_lower for kw in self.SECURITY_CONTEXTS):
                return True
        
        return False


def detect_weak_random(code: str, file_path: str = "UNKNOWN"):
    """Detect weak random number generation vulnerabilities."""
    yield from run_detector(WeakRandomDetector, code, file_path)