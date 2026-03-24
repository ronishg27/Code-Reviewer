"""
Security vulnerability detectors.

This module provides detectors for common security vulnerabilities:
- SQL Injection
- Insecure Deserialization
- Command Injection
- Weak Random Number Generation
"""

from src.analyzers.security.base import (
    BaseDetector,
    Rule,
    Severity,
    run_detector,
)

from src.analyzers.security.sql_injection_detector import (
    SQLInjectionDetector,
    detect_sql_injection,
)

from src.analyzers.security.insecure_deserialization_detector import (
    InsecureDeserializationDetector,
    detect_insecure_deserialization,
)

from src.analyzers.security.command_injection_detector import (
    CommandInjectionDetector,
    detect_command_injection,
)

from src.analyzers.security.weak_random_detector import (
    WeakRandomDetector,
    detect_weak_random,
)

from src.analyzers.security.hardcoded_secrets_detector import (
    HardcodedSecretsDetector,
    detect_hardcoded_secrets,
)

from src.analyzers.security.assert_detector import(
    AssertDetector,
    detect_assert_usage,
)

from src.analyzers.security.dangerous_functions import (
    DangerousFunctionsDetector,
    detect_dangerous_functions,
)

__all__ = [
    # Base
    'BaseDetector',
    'Rule',
    'Severity',
    'run_detector',
    # SQL Injection
    'SQLInjectionDetector',
    'detect_sql_injection',
    # Deserialization
    'InsecureDeserializationDetector',
    'detect_insecure_deserialization',
    # Command Injection
    'CommandInjectionDetector',
    'detect_command_injection',
    # Weak Random
    'WeakRandomDetector',
    'detect_weak_random',
    # Hardcoded Secrets
    'HardcodedSecretsDetector',
    'detect_hardcoded_secrets',
    # Assert Usage
    'AssertDetector',
    'detect_assert_usage',
    # Dangerous Functions
    'DangerousFunctionsDetector',
    'detect_dangerous_functions',
]