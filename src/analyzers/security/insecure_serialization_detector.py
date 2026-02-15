
import ast

from utils.get_function_name import get_function_name

from models import  make_issue


def detect_insecure_serialization(code, file_path="<unknown>"):
    """
    Detect potential insecure serialization vulnerabilities in the given code.
    Args:
        code (str): The source code to analyze.
        file_path (str): The path of the file being analyzed 

    Returns:
        list: A list of detected insecure serialization vulnerabilities.
    """


    tree = ast.parse(code)


    INSECURE_MODULES = {
            'pickle.loads': 'Use json.loads() instead',
            'pickle.load': 'Use json.load() instead',
            'yaml.load': 'Use yaml.safe_load() instead',
            'marshal.loads': 'Avoid marshal with untrusted data'
        }
    
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        
        func_name = get_function_name(node.func)

        if func_name not in INSECURE_MODULES:
            continue

        yield make_issue(
            filename=file_path,
            line=node.lineno,
            rule="Insecure Serialization",
            function=func_name,
            severity="CRITICAL",
            message=f"Use of {func_name} can lead to insecure deserialization vulnerabilities.",
            recommendation=INSECURE_MODULES[func_name]
        )

