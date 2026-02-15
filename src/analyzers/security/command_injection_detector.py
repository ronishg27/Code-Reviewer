import ast


from ...models import Issue
from utils import get_function_name


def detect_command_injection(code:str, file_path:str="unknown") :
    """
    Detect potential command injection vulnerabilities in the given code.
    Args:
        code (str): The source code to analyze.
    Returns:
        list: A list of detected command injection vulnerabilities.
    """

    DANGEROUS_FUNCTIONS = {
        'os.system': 'CRITICAL',
        'subprocess.call': 'HIGH',
        'subprocess.run': 'MEDIUM',
        'eval': 'CRITICAL',
        'exec': 'CRITICAL',
        'compile': 'HIGH',
    }

    # Parse the code into an AST
    tree= ast.parse(code)

    # Walk through the AST nodes to find function calls
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        
        # Get the full function name being called
        func_name = get_function_name(node.func)

        # Check if the function is in the list of dangerous functions
        if func_name not in DANGEROUS_FUNCTIONS:
            continue

        # check if shell=True is used 

        has_shell =False
        # for keyword in node.keywords:
        #     if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
        #         has_shell  =True
            
        has_shell  = any(
            keyword.arg == 'shell' and
            isinstance(keyword.value, ast.Constant) and
            keyword.value.value is True
            for keyword in node.keywords )
        
        severity = DANGEROUS_FUNCTIONS[func_name]
        if has_shell:
            severity = 'CRITICAL'

        
        is_dynamic = False
        if len(node.args) > 0:
            arg = node.args[0]
            
            is_dynamic = (isinstance(arg, (ast.BinOp, ast.JoinedStr, ast.Call)) or 
                        isinstance(arg, ast.Subscript) or 
                        (isinstance(arg, ast.List) and any(
                            isinstance(el, (ast.Name, ast.Subscript, ast.Call)) 
                            for el in arg.elts)
                        ))

        
        if func_name in ['eval', 'exec', 'compile'] or is_dynamic or has_shell:
            yield {
                'filename': file_path,
                'line': node.lineno,
                'type': 'command_injection',
                'function': func_name,
                'severity': severity,
                'message': f"Potential command injection vulnerability detected in function '{func_name}'",
                'recommendation': f"Avoid using this {func_name} with untrusted input. Consider using safer alternatives or sanitizing inputs."
            }



if __name__ == "__main__":
    code = """import os

def bad_os_system(user_input):
    os.system(f"ls {user_input}")      # ❌ f-string → CRITICAL

def bad_os_system_concat(user_input):
    os.system("ls " + user_input)      # ❌ concatenation

def bad_subprocess_shell(user_input):
    subprocess.run(
        f"ls {user_input}",
        shell=True                     # ❌ shell=True
    )

def bad_subprocess_call(user_input):
    subprocess.call("ls " + user_input, shell=True)  # ❌ both issues

def bad_eval(user_input):
    eval(user_input)                   # ❌ eval

def bad_exec(code):
    exec(code)                         # ❌ exec


def good_subprocess(user_input):
    subprocess.run(
        ["ls", user_input],            # ✅ list args
        shell=False
    )

"""

    for vuln in detect_command_injection(code, "example.py"):
        print(f"File: {vuln['filename']}\n Line: {vuln['line']}\n Type: {vuln['type']}\n Function: {vuln['function']}\n Severity: {vuln['severity']}\n")
