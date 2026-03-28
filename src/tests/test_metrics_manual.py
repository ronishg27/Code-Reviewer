"""
Quick manual test of the metrics module.
Run: python test_metrics_manual.py
"""

from src.analyzers.metrics import (
    calculate_all_metrics,
    ComplexityCalculator,
    CodeStatsCalculator,
    MaintainabilityCalculator,
)
import ast


def print_separator(title):
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}\n")


def test_simple_function():
    """Test with a simple function."""
    print_separator("TEST 1: Simple Function")
    
    code = '''
def add(a, b):
    """Add two numbers."""
    return a + b
'''
    
    metrics = calculate_all_metrics(code)
    
    for name, metric in metrics.items():
        print(f"Function: {name}")
        print(f"  Lines of Code: {metric.lines_of_code}")
        print(f"  Logical Lines: {metric.logical_lines}")
        print(f"  Cyclomatic Complexity: {metric.cyclomatic_complexity}")
        print(f"  Cognitive Complexity: {metric.cognitive_complexity}")
        print(f"  Maintainability Index: {metric.maintainability_index:.2f}")
        print(f"  Nesting Depth: {metric.nesting_depth}")
        print(f"  Parameters: {metric.num_parameters}")
        print(f"  Returns: {metric.num_returns}")


def test_complex_function():
    """Test with a complex function."""
    print_separator("TEST 2: Complex Function (High Complexity)")
    
    code = '''
def complex_function(data, threshold, mode):
    """Process data with complex logic."""
    results = []
    
    if data is None or len(data) == 0:
        return results
    
    for item in data:
        if item.valid:
            if mode == "strict":
                if item.value > threshold:
                    for sub_item in item.children:
                        if sub_item.active:
                            try:
                                processed = process(sub_item)
                                results.append(processed)
                            except ValueError:
                                continue
                            except TypeError:
                                break
            elif mode == "lenient":
                results.append(item)
        else:
            if item.value < 0:
                return None
    
    return results
'''
    
    metrics = calculate_all_metrics(code)
    
    for name, metric in metrics.items():
        print(f"Function: {name}")
        print(f"  Lines of Code: {metric.lines_of_code}")
        print(f"  Cyclomatic Complexity: {metric.cyclomatic_complexity}")
        print(f"  Cognitive Complexity: {metric.cognitive_complexity}")
        print(f"  Maintainability Index: {metric.maintainability_index:.2f}")
        print(f"  Nesting Depth: {metric.nesting_depth}")
        print(f"  Parameters: {metric.num_parameters}")


def test_long_function():
    """Test with a long function."""
    print_separator("TEST 3: Long Function")
    
    code = '''
def very_long_function(users, config):
    """Process users with extensive logic."""
    results = []
    errors = []
    
    # Validation section
    if not users:
        return None
    
    if config is None:
        config = get_default_config()
    
    # Processing section
    for user in users:
        if not user.active:
            continue
        
        try:
            # Step 1: Validate user
            if not validate_user(user):
                errors.append(f"Invalid user: {user.id}")
                continue
            
            # Step 2: Process user data
            user_data = {
                'id': user.id,
                'name': user.name,
                'email': user.email,
                'score': calculate_score(user)
            }
            
            # Step 3: Apply transformations
            if config.transform:
                user_data = transform(user_data)
            
            # Step 4: Validate result
            if user_data['score'] > 100:
                user_data['score'] = 100
            elif user_data['score'] < 0:
                user_data['score'] = 0
            
            results.append(user_data)
            
        except Exception as e:
            errors.append(f"Error processing {user.id}: {str(e)}")
    
    return {
        'results': results,
        'errors': errors,
        'count': len(results)
    }
'''
    
    metrics = calculate_all_metrics(code)
    
    for name, metric in metrics.items():
        print(f"Function: {name}")
        print(f"  Lines of Code: {metric.lines_of_code}")
        print(f"  Logical Lines: {metric.logical_lines}")
        print(f"  Cyclomatic Complexity: {metric.cyclomatic_complexity}")
        print(f"  Maintainability Index: {metric.maintainability_index:.2f}")
        print(f"  Parameters: {metric.num_parameters}")
        print(f"  Returns: {metric.num_returns}")


def test_multiple_functions():
    """Test with multiple functions."""
    print_separator("TEST 4: Multiple Functions")
    
    code = '''
def simple():
    return 1

def moderate(x):
    if x > 0:
        return x * 2
    else:
        return 0

def complex(data, flag):
    result = 0
    if data:
        for item in data:
            if flag:
                if item > 0:
                    result += item
                else:
                    result -= item
            else:
                result += abs(item)
    return result
'''
    
    metrics = calculate_all_metrics(code)
    
    print(f"Total functions analyzed: {len(metrics)}\n")
    
    for name, metric in metrics.items():
        print(f"Function: {name}")
        print(f"  CC: {metric.cyclomatic_complexity}, "
              f"Cognitive: {metric.cognitive_complexity}, "
              f"LOC: {metric.lines_of_code}, "
              f"MI: {metric.maintainability_index:.1f}")


def test_individual_calculators():
    """Test each calculator individually."""
    print_separator("TEST 5: Individual Calculators")
    
    code = '''
def test_function(a, b, c):
    """Test function."""
    if a > 0:
        for i in range(b):
            if i % 2 == 0:
                c += i
    return c
'''
    
    tree = ast.parse(code)
    
    # Test ComplexityCalculator
    print("ComplexityCalculator:")
    calc = ComplexityCalculator()
    results = calc.calculate(tree, code)
    for result in results:
        print(f"  {result.name}: {result.value} (rating: {result.rating})")
    
    # Test CodeStatsCalculator
    print("\nCodeStatsCalculator:")
    calc = CodeStatsCalculator()
    results = calc.calculate(tree, code)
    for result in results:
        print(f"  {result.name}: {result.value} (rating: {result.rating})")
    
    # Test MaintainabilityCalculator
    print("\nMaintainabilityCalculator:")
    calc = MaintainabilityCalculator()
    results = calc.calculate(tree, code)
    for result in results:
        print(f"  {result.name}: {result.value:.2f} (rating: {result.rating})")


def test_edge_cases():
    """Test edge cases."""
    print_separator("TEST 6: Edge Cases")
    
    test_cases = [
        ("Empty function", "def empty(): pass"),
        ("Only docstring", 'def doc_only(): """Just docs."""'),
        ("Single line", "def one_liner(x): return x * 2"),
        ("No parameters", "def no_params(): return 42"),
        ("Many parameters", "def many(a, b, c, d, e, f, g, h): return a"),
        ("Async function", "async def async_func(): return await something()"),
    ]
    
    for name, code in test_cases:
        print(f"\n{name}:")
        try:
            metrics = calculate_all_metrics(code)
            for func_name, metric in metrics.items():
                print(f"  {func_name}: CC={metric.cyclomatic_complexity}, "
                      f"LOC={metric.lines_of_code}, "
                      f"Params={metric.num_parameters}")
        except Exception as e:
            print(f"  ERROR: {e}")


def test_json_export():
    """Test JSON export functionality."""
    print_separator("TEST 7: JSON Export")
    
    code = '''
def calculate(x, y):
    if x > 0 and y > 0:
        return x + y
    elif x < 0 or y < 0:
        return abs(x - y)
    else:
        return 0
'''
    
    metrics = calculate_all_metrics(code)
    
    for name, metric in metrics.items():
        import json
        data = metric.to_dict()
        json_str = json.dumps(data, indent=2)
        print(f"Function: {name}")
        print(json_str)


def run_all_tests():
    """Run all manual tests."""
    print("\n" + "="*70)
    print("  METRICS MODULE MANUAL TESTS")
    print("="*70)
    
    test_simple_function()
    test_complex_function()
    test_long_function()
    test_multiple_functions()
    test_individual_calculators()
    test_edge_cases()
    test_json_export()
    
    print("\n" + "="*70)
    print("  ALL TESTS COMPLETED")
    print("="*70 + "\n")


if __name__ == "__main__":
    run_all_tests()