from typing import List, Dict, Any
from dataclasses import dataclass, field
from pathlib import Path
import json

from src.analyzers.security import (
    Severity,
    run_detector,
    SQLInjectionDetector,
    InsecureDeserializationDetector,
    CommandInjectionDetector,
    WeakRandomDetector,
    HardcodedSecretsDetector,
    AssertDetector,
    DangerousFunctionsDetector,
)

from src.analyzers.smells import (
    BareExceptDetector,
    DeepNestingDetector,
    LongFunctionDetector,
    
)

from src.analyzers.metrics import (
    calculate_all_metrics,
    CodeMetrics,
)

from src.models import Issue


@dataclass
class ScanResult:
    """Results from a security and quality scan."""
    file_path: str
    issues: List[Issue]
    metrics: Dict[str, CodeMetrics] = field(default_factory=dict)
    
    @property
    def total_issues(self) -> int:
        return len(self.issues)
    
    @property
    def has_critical(self) -> bool:
        return any(i.severity == 'CRITICAL' for i in self.issues)
    
    @property
    def has_high(self) -> bool:
        return any(i.severity == 'HIGH' for i in self.issues)
    
    def by_severity(self) -> Dict[str, List[Issue]]:
        """Group issues by severity."""
        # Initialize with all known severities
        result = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': [],
            'INFO': [],
            'ERROR': []
        }
        
        for issue in self.issues:
            severity = issue.severity
            if severity not in result:
                result[severity] = []  # Handle unknown severities
            result[severity].append(issue)
        
        return result
    
    def by_category(self) -> Dict[str, List[Issue]]:
        """Group issues by category."""
        result = {}
        for issue in self.issues:
            cat = issue.category if hasattr(issue, 'category') else 'UNKNOWN'
            if cat not in result:
                result[cat] = []
            result[cat].append(issue)
        return result
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get summary of metrics."""
        if not self.metrics:
            return {
                'num_functions': 0,
                'avg_complexity': 0.0,
                'avg_loc': 0.0,
                'avg_maintainability': 0.0,
                'high_complexity_count': 0,
                'long_function_count': 0,
            }
        
        num_functions = len(self.metrics)
        
        total_complexity = sum(m.cyclomatic_complexity for m in self.metrics.values())
        total_loc = sum(m.lines_of_code for m in self.metrics.values())
        total_maintainability = sum(m.maintainability_index for m in self.metrics.values())
        
        return {
            'num_functions': num_functions,
            'avg_complexity': total_complexity / num_functions,
            'avg_loc': total_loc / num_functions,
            'avg_maintainability': total_maintainability / num_functions,
            'high_complexity_count': sum(
                1 for m in self.metrics.values()
                if m.cyclomatic_complexity > 6
            ),
            'long_function_count': sum(
                1 for m in self.metrics.values()
                if m.lines_of_code > 50
            ),
        }
    
    def print_report(self, verbose: bool = False, show_metrics: bool = True) -> None:
        """Print a formatted report."""
        print(f"\n{'='*70}")
        print(f"Scan Results: {self.file_path}")
        print(f"{'='*70}")
        print(f"Total Issues: {self.total_issues}")
        
        by_sev = self.by_severity()
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            count = len(by_sev[severity])
            if count > 0:
                print(f"  {severity}: {count}")
        
        if show_metrics and self.metrics:
            print(f"\n{'='*70}")
            print("Code Metrics Summary")
            print(f"{'='*70}")
            summary = self.get_metrics_summary()
            print(f"Functions analyzed: {summary['num_functions']}")
            print(f"Average Complexity: {summary['avg_complexity']:.1f}")
            print(f"Average LOC: {summary['avg_loc']:.1f}")
            print(f"Average Maintainability: {summary['avg_maintainability']:.1f}")
            print(f"High Complexity Functions: {summary['high_complexity_count']}")
            print(f"Long Functions: {summary['long_function_count']}")
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if by_sev[severity]:
                print(f"\n{severity} Issues:")
                print("-" * 70)
                for issue in by_sev[severity]:
                    print(f"\n  Line {issue.line}: [{issue.rule}]")
                    print(f"  Function: {issue.function}")
                    print(f"  Message: {issue.message}")
                    if verbose:
                        print(f"  Recommendation: {issue.recommendation}")
    
    def to_json(self) -> str:
        """Export results as JSON."""
        data = {
            'file_path': self.file_path,
            'total_issues': self.total_issues,
            'issues': [
                {
                    'line': i.line,
                    'severity': i.severity,
                    'rule': i.rule,
                    'function': i.function,
                    'message': i.message,
                    'recommendation': i.recommendation,
                }
                for i in self.issues
            ],
            'metrics': {
                name: metrics.to_dict()
                for name, metrics in self.metrics.items()
            },
            'summary': self.get_metrics_summary(),
        }
        return json.dumps(data, indent=2)


class SecurityScanner:
    """Unified security and quality scanner."""
    
    ALL_DETECTORS: List[type] = [
        # Security
        SQLInjectionDetector,
        InsecureDeserializationDetector,
        CommandInjectionDetector,
        WeakRandomDetector,
        HardcodedSecretsDetector,
        AssertDetector,
        DangerousFunctionsDetector,
        # Quality
        BareExceptDetector,
        DeepNestingDetector,
        LongFunctionDetector,
  
    ]
    
    def __init__(
        self,
        detectors: List[type] = None,
        calculate_metrics: bool = True,
        skip_tests: bool = True
    ):
        """
        Initialize the scanner.
        
        Args:
            detectors: List of detector classes. Uses all if None.
            calculate_metrics: Whether to calculate code metrics
            skip_tests: Whether to skip test files
        """
        self.detectors = detectors or self.ALL_DETECTORS
        self.calculate_metrics = calculate_metrics
        self.skip_tests = skip_tests
    
    def scan(self, code: str, file_path: str = "UNKNOWN") -> ScanResult:
        """
        Scan code with all configured detectors and calculate metrics.
        
        Args:
            code: Source code to scan
            file_path: Path to the file being scanned
            
        Returns:
            ScanResult with issues and metrics
        """
        all_issues = []
        
        # Run all detectors
        for detector_class in self.detectors:
            for issue in run_detector(detector_class, code, file_path):
                all_issues.append(issue)
        
        # Sort and deduplicate
        severity_order = {
            'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2,
            'LOW': 3, 'INFO': 4, 'ERROR': 5
        }
        all_issues.sort(key=lambda i: (i.line, severity_order.get(i.severity, 5)))
                
        seen = set()
        unique_issues = []

        for issue in all_issues:
            # More comprehensive key
            key = (
                issue.line,
                issue.rule,
                issue.severity,
                issue.message[:50]  # First 50 chars to handle slight variations
            )
            
            if key not in seen:
                seen.add(key)
                unique_issues.append(issue)
        
        # Calculate metrics
        metrics = {}
        if self.calculate_metrics:
            metrics = calculate_all_metrics(code)
        
        return ScanResult(
            file_path=file_path,
            issues=unique_issues,
            metrics=metrics
        )
    
    def scan_file(self, file_path: str) -> ScanResult:
        """Scan a file."""
        try:
            path = Path(file_path)
            code = path.read_text(encoding='utf-8')
            return self.scan(code, file_path)
        
        except FileNotFoundError:
            return ScanResult(
                file_path=file_path,
                issues=[Issue(
                    filename=file_path,
                    line=0,
                    rule="File Not Found",
                    function="N/A",
                    severity="ERROR",
                    message=f"File not found: {file_path}",
                    recommendation="Check file path",
                    category="PARSING"
                )],
                metrics={}
            )
        
        except UnicodeDecodeError as e:
            return ScanResult(
                file_path=file_path,
                issues=[Issue(
                    filename=file_path,
                    line=0,
                    rule="Encoding Error",
                    function="N/A",
                    severity="ERROR",
                    message=f"Could not decode file (not UTF-8): {str(e)}",
                    recommendation="Ensure file is UTF-8 encoded or specify encoding",
                    category="PARSING"
                )],
                metrics={}
            )
        
        except Exception as e:
            return ScanResult(
                file_path=file_path,
                issues=[Issue(
                    filename=file_path,
                    line=0,
                    rule="Scan Error",
                    function="N/A",
                    severity="ERROR",
                    message=f"Error scanning file: {str(e)}",
                    recommendation="Check file accessibility and format",
                    category="PARSING"
                )],
                metrics={}
            )
    
    def scan_directory(
        self,
        dir_path: str,
        pattern: str = "**/*.py",
        verbose: bool = False
    ) -> List[ScanResult]:
        """Scan all Python files in a directory."""
        results = []
        path = Path(dir_path)
        
        if not path.exists():
            print(f"❌ Directory not found: {dir_path}")
            return results
        
        if not path.is_dir():
            print(f"❌ Not a directory: {dir_path}")
            return results
        
        files = list(path.glob(pattern))
        total = len(files)
        
        if verbose:
            print(f"📁 Scanning {total} files in {dir_path}...")
        
        for idx, file_path in enumerate(files, 1):
            if file_path.is_file():
                if self.skip_tests and self._is_test_file(str(file_path)):
                    if verbose:
                        print(f"  ⏭️  [{idx}/{total}] Skipped test: {file_path.name}")
                    continue
                
                if verbose:
                    print(f"  🔍 [{idx}/{total}] Scanning: {file_path.name}")
                
                try:
                    result = self.scan_file(str(file_path))
                    results.append(result)
                    
                    if verbose and result.has_critical:
                        print(f"      ⚠️  Found {result.total_issues} issues (CRITICAL)")
                    elif verbose and result.total_issues > 0:
                        print(f"      ℹ️  Found {result.total_issues} issues")
                
                except Exception as e:
                    if verbose:
                        print(f"      ❌ Error: {str(e)}")
                    continue
        
        if verbose:
            print(f"✅ Scan complete: {len(results)} files analyzed")
        
        return results
    
    def _is_test_file(self, file_path: str) -> bool:
        """Check if a file is a test file."""
        import re
        test_patterns = [
            r'test_.*\.py$', r'.*_test\.py$',
            r'tests?/.*\.py$', r'conftest\.py$',
        ]
        for pattern in test_patterns:
            if re.search(pattern, file_path, re.IGNORECASE):
                return True
        return False


def scan_code(code: str, file_path: str = "UNKNOWN") -> ScanResult:
    """Quick scan with all detectors and metrics."""
    scanner = SecurityScanner()
    return scanner.scan(code, file_path)