# test_github_integration.py
"""Test GitHub integration."""

import os

from src.core.github_fetcher import GitHubFetcher, fetch_repo
from src.core.repo_analyzer import analyze_repo

def test_parse_url():
    """Test URL parsing."""
    fetcher = GitHubFetcher()
    
    tests = [
        ("https://github.com/owner/repo", ("owner", "repo", "main")),
        ("github.com/owner/repo/tree/develop", ("owner", "repo", "develop")),
        ("owner/repo", ("owner", "repo", "main")),
    ]
    
    for url, expected in tests:
        result = fetcher.parse_repo_url(url)
        assert result == expected, f"Failed for {url}: got {result}, expected {expected}"
    
    print("✅ URL parsing works!")


def test_fetch_small_repo():
    """Test fetching a small public repository."""
    print("\n" + "="*70)
    print("Testing: Fetch Small Repository")
    print("="*70)
    
    # Use a small, simple Python repo
    repo_url = "https://github.com/psf/requests"
    
    from dotenv import load_dotenv
    load_dotenv(".env")
    
    files = fetch_repo(
        repo_url,
        max_files=5,
        verbose=True,
        token=os.getenv("GITHUB_ACCESS_TOKEN")
    )
    
    assert len(files) > 0, "Should fetch at least one file"
    assert all(path.endswith('.py') for path in files.keys()), "All files should be Python"
    
    print(f"\n✅ Successfully fetched {len(files)} file(s)")


def test_analyze_repo():
    """Test analyzing a repository."""
    print("\n" + "="*70)
    print("Testing: Analyze Repository")
    print("="*70)
    
    result = analyze_repo(
        repo_url="https://github.com/ronishg27/code-reviewer",
        # max_files=3,
        verbose=True
    )
    
    assert result.scanned_files > 0, "Should scan at least one file"
    
    print(f"\n✅ Analysis complete!")
    print(f"   Files scanned: {result.scanned_files}")
    print(f"   Total issues: {result.total_issues}")


if __name__ == "__main__":
    tests = [
        # ("URL Parsing", test_parse_url),
        # ("Fetch Repository", test_fetch_small_repo),
        ("Analyze Repository", test_analyze_repo),
    ]
    
    for name, test_func in tests:
        try:
            test_func()
        except Exception as e:
            print(f"\n❌ {name} FAILED: {e}")
            import traceback
            traceback.print_exc()