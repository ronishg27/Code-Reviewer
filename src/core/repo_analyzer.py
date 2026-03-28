
"""
Main analyzer that combines GitHub fetching with security scanning.
"""

from typing import Dict, List, Optional
from dataclasses import dataclass, field
import json
from pathlib import Path

from src.core.github_fetcher import GitHubFetcher, GitHubAPIError
from src.scanner import SecurityScanner, ScanResult


@dataclass
class RepositoryAnalysisResult:
    """Results from analyzing an entire repository."""
    repo_url: str
    total_files: int
    scanned_files: int
    file_results: Dict[str, ScanResult] = field(default_factory=dict)
    fetch_errors: List[str] = field(default_factory=list)
    
    @property
    def total_issues(self) -> int:
        """Total issues across all files."""
        return sum(r.total_issues for r in self.file_results.values())
    
    @property
    def has_critical(self) -> bool:
        """Whether any file has critical issues."""
        return any(r.has_critical for r in self.file_results.values())
    
    @property
    def critical_count(self) -> int:
        """Count of critical issues."""
        return sum(
            len(r.by_severity()['CRITICAL'])
            for r in self.file_results.values()
        )
    
    @property
    def high_count(self) -> int:
        """Count of high severity issues."""
        return sum(
            len(r.by_severity()['HIGH'])
            for r in self.file_results.values()
        )
    
    def get_summary(self) -> Dict:
        """Get summary statistics."""
        all_severities = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        
        for result in self.file_results.values():
            by_sev = result.by_severity()
            for sev in all_severities:
                all_severities[sev] += len(by_sev.get(sev, []))
        
        return {
            'repo_url': self.repo_url,
            'files_analyzed': self.scanned_files,
            'total_issues': self.total_issues,
            'by_severity': all_severities,
            'has_critical': self.has_critical,
        }
    
    def get_top_issues(self, limit: int = 10) -> List:
        """Get top N most severe issues."""
        all_issues = []
        
        for filepath, result in self.file_results.items():
            for issue in result.issues:
                all_issues.append({
                    'file': filepath,
                    'line': issue.line,
                    'severity': issue.severity,
                    'rule': issue.rule,
                    'message': issue.message,
                })
        
        # Sort by severity
        severity_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
        all_issues.sort(key=lambda x: (severity_order.get(x['severity'], 5), x['file'], x['line']))
        
        return all_issues[:limit]
    
    def print_summary(self, verbose: bool = False) -> None:
        """Print analysis summary."""
        print(f"\n{'='*70}")
        print(f"Repository Analysis Summary")
        print(f"{'='*70}")
        print(f"Repository: {self.repo_url}")
        print(f"Files Analyzed: {self.scanned_files}")
        print(f"Total Issues: {self.total_issues}")
        
        summary = self.get_summary()
        by_sev = summary['by_severity']
        
        print(f"\nBy Severity:")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if by_sev[sev] > 0:
                print(f"  {sev}: {by_sev[sev]}")
        
        if self.fetch_errors:
            print(f"\nFetch Errors: {len(self.fetch_errors)}")
            if verbose:
                for error in self.fetch_errors:
                    print(f"  - {error}")
        
        print(f"\n{'='*70}")
        print(f"Top Issues:")
        print(f"{'='*70}")
        
        for idx, issue in enumerate(self.get_top_issues(10), 1):
            print(f"\n{idx}. [{issue['severity']}] {issue['rule']}")
            print(f"   File: {issue['file']}:{issue['line']}")
            print(f"   {issue['message']}")
    
    def to_dict(self) -> Dict:
        """Convert results to a dictionary."""
        return {
            'repo_url': self.repo_url,
            'total_files': self.total_files,
            'scanned_files': self.scanned_files,
            'total_issues': self.total_issues,
            'has_critical': self.has_critical,
            'critical_count': self.critical_count,
            'high_count': self.high_count,
            'summary': self.get_summary(),
            'top_issues': self.get_top_issues(20),
            'files': {
                filepath: result.to_dict()
                for filepath, result in self.file_results.items()
            },
            'fetch_errors': self.fetch_errors,
        }
    
    def to_json(self) -> str:
        """Export as JSON."""
        return json.dumps(self.to_dict(), indent=2)
    

    
    def save_report(self, output_path: str) -> None:
        """Save detailed report to file."""
        Path(output_path).write_text(self.to_json())
        print(f"✅ Report saved to {output_path}")


class RepositoryAnalyzer:
    """Analyzes GitHub repositories for security and quality issues."""
    
    def __init__(
        self,
        github_token: Optional[str] = None,
        scanner: Optional[SecurityScanner] = None,
        verbose: bool = True
    ):
        """
        Initialize repository analyzer.
        
        Args:
            github_token: GitHub API token
            scanner: SecurityScanner instance (creates default if None)
            verbose: Print progress messages
        """
        self.fetcher = GitHubFetcher(token=github_token, verbose=verbose)
        self.scanner = scanner or SecurityScanner()
        self.verbose = verbose
    
    def analyze_repository(
        self,
        repo_url: str,
        max_files: int = 100,
        skip_tests: bool = True
    ) -> RepositoryAnalysisResult:
        """
        Analyze a GitHub repository.
        
        Args:
            repo_url: GitHub repository URL
            max_files: Maximum files to analyze
            skip_tests: Skip test files
        
        Returns:
            RepositoryAnalysisResult
        """
        # Fetch repository
        try:
            files = self.fetcher.fetch_repository(repo_url, max_files, skip_tests)
        except GitHubAPIError as e:
            print(f"❌ Failed to fetch repository: {e}")
            return RepositoryAnalysisResult(
                repo_url=repo_url,
                total_files=0,
                scanned_files=0,
                fetch_errors=[str(e)]
            )
        
        if not files:
            print(f"⚠️  No Python files found in repository")
            return RepositoryAnalysisResult(
                repo_url=repo_url,
                total_files=0,
                scanned_files=0
            )
        
        # Scan each file
        if self.verbose:
            print(f"\n{'='*70}")
            print(f"Scanning {len(files)} file(s)...")
            print(f"{'='*70}\n")
        
        results = {}
        errors = []
        
        for idx, (filepath, content) in enumerate(files.items(), 1):
            if self.verbose:
                print(f"[{idx}/{len(files)}] Scanning {filepath}...")
            
            try:
                result = self.scanner.scan(content, filepath)
                results[filepath] = result
                
                if self.verbose:
                    if result.has_critical:
                        print(f"   ⚠️  {result.total_issues} issues (CRITICAL)")
                    elif result.total_issues > 0:
                        print(f"   ℹ️  {result.total_issues} issues")
                    else:
                        print(f"   ✅ No issues")
            
            except Exception as e:
                error_msg = f"Error scanning {filepath}: {str(e)}"
                errors.append(error_msg)
                if self.verbose:
                    print(f"   ❌ {error_msg}")
        
        return RepositoryAnalysisResult(
            repo_url=repo_url,
            total_files=len(files),
            scanned_files=len(results),
            file_results=results,
            fetch_errors=errors
        )


# Convenience function
def analyze_repo(
    repo_url: str,
    github_token: Optional[str] = None,
    max_files: int = 100,
    skip_tests: bool = True,
    output_file: Optional[str] = None,
    verbose: bool = True
) -> RepositoryAnalysisResult:
    """
    Quick function to analyze a repository.
    
    Args:
        repo_url: GitHub repository URL
        github_token: GitHub API token
        max_files: Maximum files to analyze
        skip_tests: Skip test files
        output_file: Path to save JSON report (optional)
        verbose: Print progress
    
    Returns:
        RepositoryAnalysisResult
    """
    analyzer = RepositoryAnalyzer(github_token=github_token, verbose=verbose)
    result = analyzer.analyze_repository(repo_url, max_files, skip_tests)
    
    result.print_summary(verbose=verbose)
    
    if output_file:
        result.save_report(output_file)
    
    return result


if __name__ == "__main__":
    # Example: Analyze a small repository
    result = analyze_repo(
        repo_url="https://github.com/psf/requests",
        max_files=10,
        output_file="analysis_report.json",
        verbose=True
    )