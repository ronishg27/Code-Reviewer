

import ast


def get_function_name( node):
    """Extract full function name from AST node."""
    if isinstance(node, ast.Name):
        return node.id
    elif isinstance(node, ast.Attribute):
        value = get_function_name(node.value)
        return f"{value}.{node.attr}" if value else node.attr
    return ""