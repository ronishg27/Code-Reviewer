import ast
import math
import re
from typing import Dict, Iterable, Set, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from src.analyzers.security.base import BaseDetector, Rule, Severity, run_detector
from src.models import make_issue, Issue


class SecretType(Enum):
    """Types of secrets that can be detected."""
    GENERIC = "generic_secret"
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    PRIVATE_KEY = "private_key"
    URL_CREDENTIALS = "url_credentials"
    AWS_KEY = "aws_key"
    AWS_SECRET = "aws_secret"
    GITHUB_TOKEN = "github_token"
    GITLAB_TOKEN = "gitlab_token"
    SLACK_TOKEN = "slack_token"
    JWT = "jwt"
    GOOGLE_API = "google_api_key"
    STRIPE_KEY = "stripe_key"
    SENDGRID_KEY = "sendgrid_key"
    TWILIO_KEY = "twilio_key"
    AZURE_KEY = "azure_key"
    DATABASE_URL = "database_url"
    SSH_KEY = "ssh_key"
    PGP_KEY = "pgp_key"
    ENCRYPTION_KEY = "encryption_key"


@dataclass
class SecretPattern:
    """Pattern definition for secret detection."""
    pattern: str
    secret_type: SecretType
    severity: Severity
    description: str
    confidence: float = 1.0  # 0.0 to 1.0


@dataclass
class DetectedSecret:
    """Represents a detected secret."""
    secret_type: SecretType
    variable_name: str
    line: int
    severity: Severity
    confidence: float
    message: str
    recommendation: str
    masked_value: str = ""


class HardcodedSecretsDetector(BaseDetector):
    """Detector for hardcoded secrets and credentials."""
    
    DETECTOR_NAME = "Hardcoded Secrets Detector"
    DETECTOR_RULE = "Hardcoded Secret"
    
    # Variable name patterns that suggest secrets
    SECRET_VAR_PATTERNS: Dict[str, SecretType] = {
        'password': SecretType.PASSWORD,
        'passwd': SecretType.PASSWORD,
        'pwd': SecretType.PASSWORD,
        'pass': SecretType.PASSWORD,
        'api_key': SecretType.API_KEY,
        'apikey': SecretType.API_KEY,
        'api_token': SecretType.TOKEN,
        'access_key': SecretType.API_KEY,
        'secret_key': SecretType.GENERIC,
        'secret': SecretType.GENERIC,
        'token': SecretType.TOKEN,
        'auth_token': SecretType.TOKEN,
        'auth': SecretType.GENERIC,
        'bearer': SecretType.TOKEN,
        'credentials': SecretType.GENERIC,
        'aws_access': SecretType.AWS_KEY,
        'aws_secret': SecretType.AWS_SECRET,
        'private_key': SecretType.PRIVATE_KEY,
        'priv_key': SecretType.PRIVATE_KEY,
        'client_secret': SecretType.GENERIC,
        'app_secret': SecretType.GENERIC,
        'encryption_key': SecretType.ENCRYPTION_KEY,
        'signing_key': SecretType.ENCRYPTION_KEY,
        'db_password': SecretType.PASSWORD,
        'database_password': SecretType.PASSWORD,
        'mysql_pwd': SecretType.PASSWORD,
        'postgres_password': SecretType.PASSWORD,
        'redis_password': SecretType.PASSWORD,
        'mongo_password': SecretType.PASSWORD,
    }
    
    # Regex patterns for secret values
    SECRET_VALUE_PATTERNS: List[SecretPattern] = [
        # OpenAI API Key
        SecretPattern(
            pattern=r'sk-[a-zA-Z0-9]{32,}',
            secret_type=SecretType.API_KEY,
            severity=Severity.CRITICAL,
            description="OpenAI API Key"
        ),
        # GitHub Personal Access Token
        SecretPattern(
            pattern=r'ghp_[a-zA-Z0-9]{36}',
            secret_type=SecretType.GITHUB_TOKEN,
            severity=Severity.CRITICAL,
            description="GitHub Personal Access Token"
        ),
        # GitHub OAuth Access Token
        SecretPattern(
            pattern=r'gho_[a-zA-Z0-9]{36}',
            secret_type=SecretType.GITHUB_TOKEN,
            severity=Severity.CRITICAL,
            description="GitHub OAuth Access Token"
        ),
        # GitHub App Token
        SecretPattern(
            pattern=r'ghu_[a-zA-Z0-9]{36}',
            secret_type=SecretType.GITHUB_TOKEN,
            severity=Severity.CRITICAL,
            description="GitHub App User Token"
        ),
        # GitHub App Installation Token
        SecretPattern(
            pattern=r'ghs_[a-zA-Z0-9]{36}',
            secret_type=SecretType.GITHUB_TOKEN,
            severity=Severity.CRITICAL,
            description="GitHub App Installation Token"
        ),
        # GitLab Token
        SecretPattern(
            pattern=r'glpat-[a-zA-Z0-9\-]{20,}',
            secret_type=SecretType.GITLAB_TOKEN,
            severity=Severity.CRITICAL,
            description="GitLab Personal Access Token"
        ),
        # AWS Access Key ID
        SecretPattern(
            pattern=r'AKIA[0-9A-Z]{16}',
            secret_type=SecretType.AWS_KEY,
            severity=Severity.CRITICAL,
            description="AWS Access Key ID"
        ),
        # AWS Secret Access Key
        SecretPattern(
            pattern=r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
            secret_type=SecretType.AWS_SECRET,
            severity=Severity.HIGH,
            description="Potential AWS Secret Access Key",
            confidence=0.7
        ),
        # Slack Bot Token
        SecretPattern(
            pattern=r'xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}',
            secret_type=SecretType.SLACK_TOKEN,
            severity=Severity.CRITICAL,
            description="Slack Bot Token"
        ),
        # Slack User Token
        SecretPattern(
            pattern=r'xoxp-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}',
            secret_type=SecretType.SLACK_TOKEN,
            severity=Severity.CRITICAL,
            description="Slack User Token"
        ),
        # Slack Webhook URL
        SecretPattern(
            pattern=r'https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+',
            secret_type=SecretType.SLACK_TOKEN,
            severity=Severity.HIGH,
            description="Slack Webhook URL"
        ),
        # Google API Key
        SecretPattern(
            pattern=r'AIza[0-9A-Za-z\-_]{35}',
            secret_type=SecretType.GOOGLE_API,
            severity=Severity.CRITICAL,
            description="Google API Key"
        ),
        # Stripe API Keys
        SecretPattern(
            pattern=r'sk_live_[0-9a-zA-Z]{24,}',
            secret_type=SecretType.STRIPE_KEY,
            severity=Severity.CRITICAL,
            description="Stripe Live Secret Key"
        ),
        SecretPattern(
            pattern=r'sk_test_[0-9a-zA-Z]{24,}',
            secret_type=SecretType.STRIPE_KEY,
            severity=Severity.MEDIUM,
            description="Stripe Test Secret Key"
        ),
        SecretPattern(
            pattern=r'pk_live_[0-9a-zA-Z]{24,}',
            secret_type=SecretType.STRIPE_KEY,
            severity=Severity.HIGH,
            description="Stripe Live Publishable Key"
        ),
        # SendGrid API Key
        SecretPattern(
            pattern=r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',
            secret_type=SecretType.SENDGRID_KEY,
            severity=Severity.CRITICAL,
            description="SendGrid API Key"
        ),
        # Twilio API Key
        SecretPattern(
            pattern=r'SK[a-f0-9]{32}',
            secret_type=SecretType.TWILIO_KEY,
            severity=Severity.CRITICAL,
            description="Twilio API Key"
        ),
        # JWT Token
        SecretPattern(
            pattern=r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
            secret_type=SecretType.JWT,
            severity=Severity.HIGH,
            description="JWT Token"
        ),
        # RSA Private Key
        SecretPattern(
            pattern=r'-----BEGIN RSA PRIVATE KEY-----',
            secret_type=SecretType.PRIVATE_KEY,
            severity=Severity.CRITICAL,
            description="RSA Private Key"
        ),
        # Generic Private Key
        SecretPattern(
            pattern=r'-----BEGIN (?:EC |DSA |OPENSSH )?PRIVATE KEY-----',
            secret_type=SecretType.PRIVATE_KEY,
            severity=Severity.CRITICAL,
            description="Private Key"
        ),
        # PGP Private Key
        SecretPattern(
            pattern=r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
            secret_type=SecretType.PGP_KEY,
            severity=Severity.CRITICAL,
            description="PGP Private Key"
        ),
        # SSH Private Key
        SecretPattern(
            pattern=r'-----BEGIN OPENSSH PRIVATE KEY-----',
            secret_type=SecretType.SSH_KEY,
            severity=Severity.CRITICAL,
            description="SSH Private Key"
        ),
        # Azure Storage Account Key
        SecretPattern(
            pattern=r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+',
            secret_type=SecretType.AZURE_KEY,
            severity=Severity.CRITICAL,
            description="Azure Storage Connection String"
        ),
        # Heroku API Key
        SecretPattern(
            pattern=r'[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}',
            secret_type=SecretType.API_KEY,
            severity=Severity.HIGH,
            description="Heroku API Key"
        ),
        # NPM Token
        SecretPattern(
            pattern=r'npm_[a-zA-Z0-9]{36}',
            secret_type=SecretType.TOKEN,
            severity=Severity.CRITICAL,
            description="NPM Access Token"
        ),
        # Discord Bot Token
        SecretPattern(
            pattern=r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}',
            secret_type=SecretType.TOKEN,
            severity=Severity.CRITICAL,
            description="Discord Bot Token"
        ),
    ]
    
    # URL with embedded credentials pattern
    URL_CREDENTIAL_PATTERN = re.compile(
        r'(?P<scheme>\w+)://(?P<user>[^:]+):(?P<pass>[^@]+)@(?P<host>[^/]+)'
    )
    
    # Database URL patterns
    DATABASE_URL_PATTERNS = [
        re.compile(r'(?:postgres|postgresql|mysql|mongodb|redis|amqp)://[^:]+:[^@]+@'),
    ]
    
    # Placeholders that should not be flagged
    PLACEHOLDERS: Set[str] = {
        '', 'xxx', 'yyy', 'zzz',
        'your_api_key', 'your_api_key_here', 'your-api-key',
        'your_token', 'your_token_here', 'your-token',
        'your_password', 'your_password_here', 'your-password',
        'your_secret', 'your_secret_here', 'your-secret',
        'change_me', 'changeme', 'change-me',
        'replace_me', 'replaceme', 'replace-me',
        'todo', 'fixme', 'placeholder',
        'example', 'sample', 'test', 'testing',
        'dummy', 'fake', 'mock',
        'insert_key_here', 'insert_token_here',
        'api_key_here', 'token_here', 'secret_here',
        'none', 'null', 'undefined', 'empty',
        '<your_api_key>', '<api_key>', '<token>', '<password>',
        '${api_key}', '${token}', '${password}', '${secret}',
        'env.api_key', 'env.token', 'process.env.api_key',
        'xxxxxxxx', 'xxxxxxxxxxxx', '********',
    }
    
    # Allowlist of variable names
    VARIABLE_ALLOWLIST: Set[str] = {
        'debug_token', 'safe_config', 'test_mode',
        'is_authenticated', 'has_token', 'token_type',
        'password_field', 'password_input', 'password_hash',
        'hashed_password', 'password_salt',
    }
    
    # File patterns to skip (test files, examples, etc.)
    SKIP_FILE_PATTERNS: List[str] = [
        r'test_.*\.py$',
        r'.*_test\.py$',
        r'.*tests?/.*\.py$',
        r'conftest\.py$',
        r'example.*\.py$',
        r'sample.*\.py$',
        r'mock.*\.py$',
        r'fixture.*\.py$',
    ]
    
    # Minimum entropy threshold for suspicious strings
    MIN_ENTROPY_THRESHOLD = 3.5
    MIN_SECRET_LENGTH = 8
    
    def __init__(self, file_path: str = "UNKNOWN", skip_tests: bool = True):
        super().__init__(file_path)
        self.skip_tests = skip_tests
        self.seen_secrets: Set[Tuple[int, str]] = set()
        
        # Check if this file should be skipped
        self.should_skip_file = self._should_skip_file()
    
    def _should_skip_file(self) -> bool:
        """Check if the file should be skipped based on patterns."""
        if not self.skip_tests:
            return False
        
        for pattern in self.SKIP_FILE_PATTERNS:
            if re.search(pattern, self.file_path, re.IGNORECASE):
                return True
        return False
    
    def _on_call(self, node: ast.Call, func_name: str, resolved_name: str) -> None:
        """Check function calls for hardcoded secrets in arguments."""
        try:
            if self.should_skip_file:
                return
            
            # Check keyword arguments
            for keyword in node.keywords:
                if keyword.arg and isinstance(keyword.value, ast.Constant):
                    if isinstance(keyword.value.value, str):
                        self._check_secret(
                            node=keyword.value,
                            var_name=keyword.arg,
                            value=keyword.value.value,
                            context=f"function argument in {func_name}()"
                        )
            
            # Check for specific dangerous function calls
            if resolved_name in {'connect', 'create_engine', 'Connection'}:
                self._check_connection_arguments(node, func_name)


        except Exception as e:
            import logging
            logging.warning(f"Hardcoded secrets detector error at line {node.lineno}: {e}")
            return
    
    def _on_assign(self, node: ast.Assign) -> None:
        """Check assignments for hardcoded secrets."""
        if self.should_skip_file:
            return
        
        value_node = node.value
        
        # Check string literals
        if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
            self._check_assignment_targets(node.targets, value_node.value, node)
        
        # Check dictionary literals
        elif isinstance(value_node, ast.Dict):
            self._check_dict_literal(value_node, node)
    
    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Check annotated assignments (e.g., api_key: str = "secret")."""
        if self.should_skip_file:
            self.generic_visit(node)
            return
        
        if node.value and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                targets = [node.target] if node.target else []
                self._check_assignment_targets(targets, node.value.value, node)
        
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Check function definitions for default argument secrets."""
        if not self.should_skip_file:
            self._check_function_defaults(node)
        super().visit_FunctionDef(node)
    
    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Check async function definitions for default argument secrets."""
        if not self.should_skip_file:
            self._check_function_defaults(node)
        super().visit_AsyncFunctionDef(node)
    
    def _check_function_defaults(self, node: ast.FunctionDef) -> None:
        """Check function default arguments for secrets."""
        # Check regular arguments
        defaults = node.args.defaults
        args = node.args.args[-len(defaults):] if defaults else []
        
        for arg, default in zip(args, defaults):
            if isinstance(default, ast.Constant) and isinstance(default.value, str):
                self._check_secret(
                    node=default,
                    var_name=arg.arg,
                    value=default.value,
                    context=f"default argument in {node.name}()"
                )
        
        # Check keyword-only arguments
        kw_defaults = node.args.kw_defaults
        for arg, default in zip(node.args.kwonlyargs, kw_defaults):
            if default and isinstance(default, ast.Constant) and isinstance(default.value, str):
                self._check_secret(
                    node=default,
                    var_name=arg.arg,
                    value=default.value,
                    context=f"default kwarg in {node.name}()"
                )
    
    def _check_assignment_targets(
        self,
        targets: List[ast.AST],
        value: str,
        node: ast.AST
    ) -> None:
        """Check assignment targets for secret patterns."""
        for target in targets:
            var_name = self._extract_var_name(target)
            if var_name:
                self._check_secret(node, var_name, value)
    
    def _check_dict_literal(self, dict_node: ast.Dict, parent_node: ast.AST) -> None:
        """Check dictionary literals for secrets."""
        for key, value in zip(dict_node.keys, dict_node.values):
            if isinstance(key, ast.Constant) and isinstance(key.value, str):
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    self._check_secret(
                        node=value,
                        var_name=key.value,
                        value=value.value,
                        context="dictionary literal"
                    )
    
    def _check_connection_arguments(self, node: ast.Call, func_name: str) -> None:
        """Check database connection calls for embedded credentials."""
        # Check first positional argument (often connection string)
        if node.args and isinstance(node.args[0], ast.Constant):
            value = node.args[0].value
            if isinstance(value, str):
                for pattern in self.DATABASE_URL_PATTERNS:
                    if pattern.search(value):
                        self._report_url_credentials(node.args[0], func_name, value)
                        return
    
    def _extract_var_name(self, target: ast.AST) -> Optional[str]:
        """Extract variable name from assignment target."""
        if isinstance(target, ast.Name):
            return target.id
        elif isinstance(target, ast.Attribute):
            return target.attr
        elif isinstance(target, ast.Subscript):
            if isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                return target.slice.value
        return None
    
    def _check_secret(
        self,
        node: ast.AST,
        var_name: str,
        value: str,
        context: str = ""
    ) -> None:
        """Check if a value is a potential hardcoded secret."""
        # Skip if already seen
        key = (node.lineno, var_name.lower())
        if key in self.seen_secrets:
            return
        
        # Skip allowlisted variables
        if var_name.lower() in self.VARIABLE_ALLOWLIST:
            return
        
        # Skip placeholders
        if self._is_placeholder(value):
            return
        
        # Skip values that are too short
        if len(value) < self.MIN_SECRET_LENGTH:
            return
        
        # Check for URL credentials
        url_match = self.URL_CREDENTIAL_PATTERN.search(value)
        if url_match:
            self._report_url_credentials(node, var_name, value, context)
            self.seen_secrets.add(key)
            return
        
        # Check against known secret patterns
        for pattern in self.SECRET_VALUE_PATTERNS:
            if re.search(pattern.pattern, value):
                self._report_pattern_match(node, var_name, pattern, context)
                self.seen_secrets.add(key)
                return
        
        # Check for suspicious variable names with high entropy values
        secret_type = self._get_secret_type_from_name(var_name)
        if secret_type:
            entropy = self._calculate_entropy(value)
            if entropy >= self.MIN_ENTROPY_THRESHOLD or len(value) >= 20:
                self._report_suspicious_variable(
                    node, var_name, secret_type, entropy, context
                )
                self.seen_secrets.add(key)
    
    def _is_placeholder(self, value: str) -> bool:
        """Check if a value is a placeholder."""
        normalized = value.lower().strip()
        
        # Check direct match
        if normalized in self.PLACEHOLDERS:
            return True
        
        # Check patterns
        placeholder_patterns = [
            r'^<.*>$',  # <placeholder>
            r'^\$\{.*\}$',  # ${placeholder}
            r'^%\(.*\)s$',  # %(placeholder)s
            r'^\{\{.*\}\}$',  # {{placeholder}}
            r'^x+$',  # xxxx
            r'^\*+$',  # ****
            r'^\.+$',  # ....
        ]
        
        for pattern in placeholder_patterns:
            if re.match(pattern, normalized):
                return True
        
        return False
    
    def _get_secret_type_from_name(self, var_name: str) -> Optional[SecretType]:
        """Get secret type based on variable name patterns."""
        lower_name = var_name.lower()
        
        for pattern, secret_type in self.SECRET_VAR_PATTERNS.items():
            if pattern in lower_name:
                return secret_type
        
        return None
    
    def _calculate_entropy(self, value: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not value:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for char in value:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        length = len(value)
        entropy = 0.0
        for count in freq.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _mask_secret(self, value: str, visible_chars: int = 4) -> str:
        """Mask a secret value for safe display."""
        if len(value) <= visible_chars * 2:
            return '*' * len(value)
        return value[:visible_chars] + '*' * (len(value) - visible_chars * 2) + value[-visible_chars:]
    
    def _report_pattern_match(
        self,
        node: ast.AST,
        var_name: str,
        pattern: SecretPattern,
        context: str = ""
    ) -> None:
        """Report a secret detected by pattern matching."""
        context_str = f" ({context})" if context else self.get_context_string()
        
        rule = Rule(
            severity=pattern.severity,
            message=f"{pattern.description} detected in '{var_name}'{context_str}",
            recommendation="Remove hardcoded secrets. Use environment variables, secret managers (AWS Secrets Manager, HashiCorp Vault), or configuration files excluded from version control."
        )
        
        self.report_issue(node, rule, var_name)
    
    def _report_url_credentials(
        self,
        node: ast.AST,
        var_name: str,
        value: str,
        context: str = ""
    ) -> None:
        """Report URL with embedded credentials."""
        context_str = f" ({context})" if context else self.get_context_string()
        masked = self._mask_connection_string(value)
        
        rule = Rule(
            severity=Severity.CRITICAL,
            message=f"URL with embedded credentials in '{var_name}'{context_str}: {masked}",
            recommendation="Remove credentials from URLs. Use environment variables or secret managers to store credentials separately."
        )
        
        self.report_issue(node, rule, var_name)
    
    def _report_suspicious_variable(
        self,
        node: ast.AST,
        var_name: str,
        secret_type: SecretType,
        entropy: float,
        context: str = ""
    ) -> None:
        """Report a suspicious variable with high entropy value."""
        context_str = f" ({context})" if context else self.get_context_string()
        
        severity = Severity.HIGH
        if secret_type in {SecretType.PASSWORD, SecretType.PRIVATE_KEY, SecretType.API_KEY}:
            severity = Severity.CRITICAL
        
        rule = Rule(
            severity=severity,
            message=f"Potential hardcoded {secret_type.value} in '{var_name}'{context_str} (entropy: {entropy:.2f})",
            recommendation="Review this variable. If it contains a secret, use environment variables or a secret manager instead."
        )
        
        self.report_issue(node, rule, var_name)
    
    def _mask_connection_string(self, url: str) -> str:
        """Mask password in connection string."""
        match = self.URL_CREDENTIAL_PATTERN.search(url)
        if match:
            return url.replace(match.group('pass'), '****')
        return url


def detect_hardcoded_secrets(
    code: str,
    file_path: str = "UNKNOWN",
    skip_tests: bool = True
) -> Iterable[Issue]:
    """
    Detect hardcoded secrets in the given code.
    
    Args:
        code: The source code to analyze
        file_path: The path of the file being analyzed
        skip_tests: Whether to skip test files
        
    Yields:
        Issue objects for each detected secret
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
    
    # Add parent references
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent
    
    detector = HardcodedSecretsDetector(file_path, skip_tests)
    detector.visit(tree)
    
    yield from detector.issues


if __name__ == "__main__":
    sample_code = '''
import os
from db import connect

# Pattern-matched secrets (CRITICAL)
API_KEY = "sk-1234567890abcdef1234567890abcdef"
GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
GOOGLE_API_KEY = "AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI"
STRIPE_KEY = "sk_live_1234567890abcdef1234567890abcdef"
SENDGRID_KEY = "SG.abcdefghijklmnopqrstuv.wxyzABCDEFGHIJKLMNOPQRSTUVWXYZ123456789012"
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"

# Annotated assignment
API_TOKEN: str = "sk-abcdef1234567890abcdef1234567890"

# URL credentials (CRITICAL)
DATABASE_URL = "postgres://admin:supersecretpassword@localhost:5432/mydb"
REDIS_URL = "redis://user:p@ssw0rd!@redis.example.com:6379/0"

# Dictionary literals
config = {
    "api_key": "sk-1234567890abcdef1234567890abcdef",
    "password": "admin123456789",
    "database": "myapp"  # Safe - not a secret pattern
}

# Subscript assignment  
settings["password"] = "mysupersecretpassword123"
settings["debug"] = "true"  # Safe

# Suspicious variable names with high entropy (HIGH)
SECRET_KEY = "a8f5f167f44f4964e6c998dee827110c"
ENCRYPTION_KEY = "0123456789abcdef0123456789abcdef"

# Function default arguments
def connect_db(host="localhost", password="defaultpassword123"):
    pass

def get_api(key="sk-testkey1234567890abcdef12345678"):
    pass

# Class attribute
class Config:
    API_SECRET = "verysecretapikey1234567890123456"

# Private key
PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...
-----END RSA PRIVATE KEY-----"""

# Safe examples - should NOT be flagged
PLACEHOLDER_KEY = "YOUR_API_KEY_HERE"
DEBUG_MODE = "true"
APP_NAME = "MyApplication"
VERSION = "1.0.0"
EMPTY_PASSWORD = ""
TEST_TOKEN = "test"
TEMPLATE_VAR = "${API_KEY}"
SAFE_CONFIG = "debug_mode"  # Allowlisted

# Environment variable references (safe)
ACTUAL_KEY = os.environ.get("API_KEY")
'''

    print("Hardcoded Secrets Detection Report")
    print("=" * 80)
    
    issues_by_severity = {
        'CRITICAL': [],
        'HIGH': [],
        'MEDIUM': [],
        'LOW': [],
        'INFO': []
    }
    
    for issue in detect_hardcoded_secrets(sample_code, "sample.py", skip_tests=False):
        issues_by_severity[issue.severity].append(issue)
    
    total = sum(len(issues) for issues in issues_by_severity.values())
    print(f"\nTotal Issues Found: {total}\n")
    
    for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
        if issues_by_severity[severity]:
            print(f"\n{severity} Issues ({len(issues_by_severity[severity])}):")
            print("-" * 80)
            for issue in issues_by_severity[severity]:
                print(f"\n  Line {issue.line}: {issue.function}")
                print(f"  Message: {issue.message}")
                print(f"  Recommendation: {issue.recommendation}")
    
    print("\n" + "=" * 80)
    print("\nBEST PRACTICES FOR SECRET MANAGEMENT:")
    print("-" * 80)
    print("""
1. Use environment variables:
   API_KEY = os.environ.get("API_KEY")

2. Use secret managers:
   - AWS Secrets Manager
   - HashiCorp Vault  
   - Azure Key Vault
   - Google Secret Manager

3. Use configuration files excluded from git:
   - .env files (add to .gitignore)
   - config.local.py

4. For development:
   - Use python-dotenv to load .env files
   - Use placeholder values in committed code

5. Pre-commit hooks:
   - Use tools like detect-secrets, gitleaks, or truffleHog
""")