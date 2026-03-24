import ast

def get_function_name(node, max_depth: int = 10, _depth: int = 0):
    """
    Extract full function name from AST node.
    
    Args:
        node: AST node to extract name from
        max_depth: Maximum recursion depth to prevent infinite loops
        _depth: Current recursion depth (internal use)
    
    Returns:
        Function name as string, or empty string if not extractable
    """
    # Prevent infinite recursion
    if _depth > max_depth:
        return ""
    
    if isinstance(node, ast.Name):
        return node.id
    
    elif isinstance(node, ast.Attribute):
        value = get_function_name(node.value, max_depth, _depth + 1)
        if value:
            return f"{value}.{node.attr}"
        return node.attr
    
    elif isinstance(node, ast.Call):
        # Handle chained calls: func()()
        return get_function_name(node.func, max_depth, _depth + 1)
    
    return ""