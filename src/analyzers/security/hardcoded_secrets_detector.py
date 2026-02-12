

import ast
import math
import re


def detect_hardcoded_secrets(file_content: str, file_path: str="unknown"):
    """
    Detect hardcoded secrets in the given file content.
    Args:
        file_content (str): The content of the file to analyze.
        file_path (str): The path of the file being analyzed (for reporting purposes).
    Returns:
        list: A list of detected hardcoded secrets.
    """

    # Pattern 1: Variable names that suggest secrets
    SECRET_VAR_PATTERNS = [
        'password', 'passwd', 'pwd',
        'api_key', 'apikey', 'api_token',
        'secret', 'token', 'auth',
        'aws_access', 'aws_secret',
        'private_key', 'client_secret'
    ]

    
    # Pattern 2: String patterns that look like secrets
    SECRET_VALUE_PATTERNS = {
        'api_key': r'sk-[a-zA-Z0-9]{32,}',  # OpenAI style
        'github_token': r'ghp_[a-zA-Z0-9]{36}',
        'aws_key': r'AKIA[0-9A-Z]{16}',
        'jwt': r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.',
        # 'generic_key': r'[a-zA-Z0-9]{32,}'  # Long random strings
    }

    # Pattern 3: URLs with embedded credentials
    URL_CRED_PATTERN = r'://[^:/]+:[^@]+@'

    # Pattern 4: Common placeholders that should not be considered secrets
    PLACEHOLDERS = {'', 'YOUR_API_KEY', 'CHANGE_ME', 'TODO', 'YOUR_PASSWORD_HERE',    'PLACEHOLDER', 'EXAMPLE', 'TEST', 'DUMMY', 'REPLACE_ME', 'XXX', 'YYY', 'ZZZ'}

    # Allowlist of variable names that may look like secrets but are not (e.g., for testing or debugging)
    ALLOWLIST = {
        "DEBUG_TOKEN",
        "SAFE_CONFIG"
    }


    tree = ast.parse(file_content)

    for node in ast.walk(tree):

        seen = set()  # To avoid duplicate detections in the same line

        # targetting: - variable assignments (e.g., password = "secret")
        if not isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign)):
            continue
        
        
        # getting the value that is being assigned to the variable
        value_node = node.value

        # only consider string literals
        if not isinstance(value_node, ast.Constant) or not isinstance(value_node.value, str):
            continue

        # getting the string value
        value = value_node.value

        # skip placeholders
        if value in PLACEHOLDERS:
            continue

        # get targets of the assignment (e.g., variable names)
        targets = []
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AugAssign):
            targets = [node.target]
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        
        # looping through the targets to check for variable names that suggest secrets
        for target in targets:
            var_name = None
            if isinstance(target, ast.Name):
                var_name = target.id
            elif isinstance(target, ast.Attribute):
                var_name = target.attr
            elif isinstance(target, ast.Subscript):
                if isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                    var_name = target.slice.value

            
            if not var_name or var_name in ALLOWLIST:
                continue

            key = (node.lineno, var_name)
        
            if key in seen:
                continue
            else:
                seen.add(key)

            lname =var_name.lower()
            
            # URL with embedded credentials
            if re.search(URL_CRED_PATTERN, value):
                yield getIssueMessage(file_path, node, var_name, 'hardcoded_url_credentials')
                continue
            
            for secret_type, pattern in SECRET_VALUE_PATTERNS.items():
                if re.search(pattern, value):
                    yield getSecretIssue(file_path, node, var_name, secret_type)
                    break
                
            else:
                # High Entropy + suspicious variable name
                has_secret_name = any(p in lname for p in SECRET_VAR_PATTERNS)
                high_entropy = len(value) >= 20 and calculate_entropy(value) > 3.5

                if(
                        has_secret_name and high_entropy
                ):
                    yield getIssueMessage(file_path, node, var_name, 'suspicious_variable_name')
                    break



def calculate_entropy(s):
    """Calculate the Shannon entropy of a string."""   
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

    
ISSUE_TYPES = {
    'hardcoded_secrets': {
        'severity': 'CRITICAL',
        'message': 'Hardcoded secrets detected',
        'recommendation': 'Remove hardcoded secrets and use environment variables or secure vaults instead'
    },
    'hardcoded_url_credentials': {
        'severity': 'CRITICAL',
        'message': 'Hardcoded URL credentials detected',
        'recommendation': 'Remove hardcoded URL credentials and use environment variables or secure vaults instead'
    },
    'suspicious_variable_name': {
        'severity': 'HIGH',
        'message': 'Suspicious variable name with potential hardcoded secret detected',
        'recommendation': 'Review the variable and ensure it does not contain hardcoded secrets'
    }

}


def getIssueMessage(file_path, node, var_name, type):
    return{
        'filename': file_path,
        'type': ISSUE_TYPES[type]['message'],
        'severity': ISSUE_TYPES[type]['severity'],
        'line': node.lineno,
        'variable': var_name,
        'message': ISSUE_TYPES[type]['message'],
        'recommendation': ISSUE_TYPES[type]['recommendation']
    }



def getSecretIssue(file_path, node, var_name, secret_type):
    return{
        'filename': file_path,
        'type': f'Hardcoded Secret Detected ({secret_type})',
        'severity': 'CRITICAL',
        'line': node.lineno,
        'variable': var_name,
        'message': f'Hardcoded secret ({secret_type}) detected in variable "{var_name}"',
        'recommendation': 'Remove hardcoded secrets and use environment variables or secure vaults instead'
    }




if __name__ == "__main__":
    sample_code = """
API_KEY = "sk-1234567890abcdef1234567890abcdef"
API_KEY1: str = "sk-1234567890abcdef1234567890abcdef" 
config["API_KEY"] = "abc"
settings['password'] = "secret"
PASSWORD = "admin123"
DATABASE_URL = "postgres://user:pass@localhost/db"
SAFE_CONFIG = "debug_mode"
GITHUB_TOKEN = "ghp_1234567890abcdef1234567890abcdef1234"
AWS_KEY = "AKIA1234567890ABCDEF"
JWT_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
"""

    for issue in detect_hardcoded_secrets(sample_code, "sample.py"):
        print(f"Issue detected: {issue['message']} at line {issue['line']} in {issue['filename']}")




