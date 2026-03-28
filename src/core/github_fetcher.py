# src/github_fetcher.py
"""
GitHub API integration for fetching repository contents.
"""

import os
import base64
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import requests
from pathlib import Path


@dataclass
class RateLimitInfo:
    """GitHub API rate limit information."""
    limit: int
    remaining: int
    reset_timestamp: int
    
    @property
    def reset_time_str(self) -> str:
        """Get human-readable reset time."""
        from datetime import datetime
        dt = datetime.fromtimestamp(self.reset_timestamp)
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    
    def __str__(self) -> str:
        return f"Rate Limit: {self.remaining}/{self.limit} (resets at {self.reset_time_str})"


class GitHubAPIError(Exception):
    """Custom exception for GitHub API errors."""
    pass


class GitHubFetcher:
    """
    Fetch Python files from GitHub repositories.
    
    Features:
    - Supports public and private repositories (with token)
    - Handles API rate limiting
    - Filters Python files automatically
    - Progress reporting
    """
    
    BASE_URL = "https://api.github.com"
    
    def __init__(self, token: Optional[str] = None, verbose: bool = False):
        """
        Initialize GitHub fetcher.
        
        Args:
            token: GitHub personal access token (optional for public repos)
            verbose: Whether to print progress messages
        """
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.verbose = verbose
        self.session = requests.Session()
        
        # Set up headers
        self.headers = {
            "Accept": "application/vnd.github.v3+json",
        }
        
        if self.token:
            self.headers["Authorization"] = f"token {self.token}"
            if self.verbose:
                print("✅ Using authenticated requests (5,000 req/hour)")
        else:
            if self.verbose:
                print("⚠️  Using unauthenticated requests (60 req/hour)")
                print("   Set GITHUB_TOKEN env var for higher rate limit")
    
    def parse_repo_url(self, url: str) -> Tuple[str, str, str]:
        """
        Parse GitHub repository URL.
        
        Args:
            url: GitHub URL (various formats supported)
        
        Returns:
            Tuple of (owner, repo, branch)
        
        Examples:
            >>> parse_repo_url("https://github.com/owner/repo")
            ('owner', 'repo', 'main')
            >>> parse_repo_url("github.com/owner/repo/tree/develop")
            ('owner', 'repo', 'develop')
        """
        # Remove protocol and trailing slash
        url = url.replace("https://", "").replace("http://", "").rstrip("/")
        
        # Remove github.com prefix
        if url.startswith("github.com/"):
            url = url[11:]
        
        parts = url.split("/")
        
        if len(parts) < 2:
            raise ValueError(f"Invalid GitHub URL: {url}")
        
        owner = parts[0]
        repo = parts[1]
        
        # Check if branch is specified
        branch = "main"
        if len(parts) >= 4 and parts[2] == "tree":
            branch = parts[3]
        
        return owner, repo, branch
    
    def get_rate_limit(self) -> RateLimitInfo:
        """
        Get current rate limit status.
        
        Returns:
            RateLimitInfo object
        """
        response = self.session.get(
            f"{self.BASE_URL}/rate_limit",
            headers=self.headers
        )
        
        if response.status_code != 200:
            raise GitHubAPIError(f"Failed to get rate limit: {response.status_code}")
        
        data = response.json()
        core = data["resources"]["core"]
        
        return RateLimitInfo(
            limit=core["limit"],
            remaining=core["remaining"],
            reset_timestamp=core["reset"]
        )
    
    def check_rate_limit(self) -> None:
        """Check rate limit and wait if necessary."""
        try:
            rate_limit = self.get_rate_limit()
            
            if self.verbose:
                print(f"📊 {rate_limit}")
            
            if rate_limit.remaining < 10:
                wait_time = rate_limit.reset_timestamp - time.time() + 5
                if wait_time > 0:
                    if self.verbose:
                        print(f"⏳ Rate limit low. Waiting {int(wait_time)}s until reset...")
                    time.sleep(wait_time)
        
        except Exception as e:
            if self.verbose:
                print(f"⚠️  Could not check rate limit: {e}")
    
    def get_default_branch(self, owner: str, repo: str) -> str:
        """
        Get the default branch of a repository.
        
        Args:
            owner: Repository owner
            repo: Repository name
        
        Returns:
            Default branch name (e.g., 'main' or 'master')
        """
        url = f"{self.BASE_URL}/repos/{owner}/{repo}"
        
        response = self.session.get(url, headers=self.headers)
        
        if response.status_code == 404:
            raise GitHubAPIError(f"Repository not found: {owner}/{repo}")
        elif response.status_code == 403:
            raise GitHubAPIError(f"Access forbidden. Check your token permissions.")
        elif response.status_code != 200:
            raise GitHubAPIError(f"Failed to get repo info: {response.status_code}")
        
        data = response.json()
        return data.get("default_branch", "main")
    
    def get_repository_tree(
        self,
        owner: str,
        repo: str,
        branch: str = None
    ) -> List[Dict]:
        """
        Get the file tree of a repository.
        
        Args:
            owner: Repository owner
            repo: Repository name
            branch: Branch name (if None, uses default branch)
        
        Returns:
            List of file/directory entries
        """
        # Get default branch if not specified
        if branch is None:
            branch = self.get_default_branch(owner, repo)
        
        if self.verbose:
            print(f"📂 Fetching tree for {owner}/{repo} (branch: {branch})...")
        
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/git/trees/{branch}?recursive=1"
        
        response = self.session.get(url, headers=self.headers)
        
        if response.status_code == 404:
            # Try alternate branch names
            alternates = ["master", "develop", "dev"]
            for alt_branch in alternates:
                if alt_branch != branch:
                    try:
                        if self.verbose:
                            print(f"   Branch '{branch}' not found, trying '{alt_branch}'...")
                        return self.get_repository_tree(owner, repo, alt_branch)
                    except GitHubAPIError:
                        continue
            
            raise GitHubAPIError(f"Branch '{branch}' not found in {owner}/{repo}")
        
        elif response.status_code != 200:
            raise GitHubAPIError(f"Failed to get repository tree: {response.status_code}")
        
        data = response.json()
        
        if data.get("truncated", False):
            if self.verbose:
                print("⚠️  Repository tree is large and may be truncated")
        
        return data.get("tree", [])
    
    def get_file_content(
        self,
        owner: str,
        repo: str,
        path: str,
        branch: str = None
    ) -> str:
        """
        Get the content of a single file.
        
        Args:
            owner: Repository owner
            repo: Repository name
            path: File path in repository
            branch: Branch name (if None, uses default branch)
        
        Returns:
            File content as string
        """
        if branch is None:
            branch = self.get_default_branch(owner, repo)
        
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/contents/{path}?ref={branch}"
        
        response = self.session.get(url, headers=self.headers)
        
        if response.status_code == 404:
            raise GitHubAPIError(f"File not found: {path}")
        elif response.status_code != 200:
            raise GitHubAPIError(f"Failed to get file content: {response.status_code}")
        
        data = response.json()
        
        # Decode base64 content
        content_b64 = data.get("content", "")
        content_bytes = base64.b64decode(content_b64)
        
        try:
            content = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # Try other encodings
            for encoding in ["latin-1", "cp1252"]:
                try:
                    content = content_bytes.decode(encoding)
                    if self.verbose:
                        print(f"⚠️  File {path} decoded with {encoding} (not UTF-8)")
                    break
                except UnicodeDecodeError:
                    continue
            else:
                raise GitHubAPIError(f"Could not decode file {path}")
        
        return content
    
    def fetch_python_files(
        self,
        owner: str,
        repo: str,
        branch: str = None,
        max_files: int = None,
        skip_tests: bool = True
    ) -> Dict[str, str]:
        """
        Fetch all Python files from a repository.
        
        Args:
            owner: Repository owner
            repo: Repository name
            branch: Branch name (if None, uses default branch)
            max_files: Maximum number of files to fetch (None = unlimited)
            skip_tests: Whether to skip test files
        
        Returns:
            Dictionary mapping file paths to file contents
        """
        self.check_rate_limit()
        
        # Get repository tree
        tree = self.get_repository_tree(owner, repo, branch)
        
        # Filter Python files
        python_files = [
            entry for entry in tree
            if entry["type"] == "blob" and entry["path"].endswith(".py")
        ]
        
        if skip_tests:
            import re
            test_patterns = [
                r'test_.*\.py$', r'.*_test\.py$',
                r'tests?/.*\.py$', r'conftest\.py$',
            ]
            
            python_files = [
                f for f in python_files
                if not any(re.search(p, f["path"], re.IGNORECASE) for p in test_patterns)
            ]
        
        total_files = len(python_files)
        
        if max_files and total_files > max_files:
            if self.verbose:
                print(f"⚠️  Found {total_files} Python files, limiting to {max_files}")
            python_files = python_files[:max_files]
        
        if self.verbose:
            print(f"📄 Found {len(python_files)} Python file(s) to fetch")
        
        # Fetch file contents
        files_content = {}
        
        for idx, file_entry in enumerate(python_files, 1):
            path = file_entry["path"]
            
            if self.verbose:
                print(f"   [{idx}/{len(python_files)}] Fetching {path}...")
            
            try:
                content = self.get_file_content(owner, repo, path, branch)
                files_content[path] = content
            
            except GitHubAPIError as e:
                if self.verbose:
                    print(f"      ❌ Error fetching {path}: {e}")
                continue
            
            # Check rate limit periodically
            if idx % 10 == 0:
                self.check_rate_limit()
        
        if self.verbose:
            print(f"✅ Fetched {len(files_content)} file(s) successfully")
        
        return files_content
    
    def fetch_repository(
        self,
        repo_url: str,
        max_files: int = None,
        skip_tests: bool = True
    ) -> Dict[str, str]:
        """
        Fetch all Python files from a GitHub repository URL.
        
        Args:
            repo_url: GitHub repository URL
            max_files: Maximum number of files to fetch
            skip_tests: Whether to skip test files
        
        Returns:
            Dictionary mapping file paths to file contents
        """
        owner, repo, branch = self.parse_repo_url(repo_url)
        
        if self.verbose:
            print(f"\n{'='*70}")
            print(f"Fetching Repository: {owner}/{repo}")
            print(f"{'='*70}\n")
        
        return self.fetch_python_files(owner, repo, branch, max_files, skip_tests)


# Convenience function
def fetch_repo(
    repo_url: str,
    token: Optional[str] = None,
    max_files: int = 100,
    skip_tests: bool = True,
    verbose: bool = True
) -> Dict[str, str]:
    """
    Quick function to fetch a repository.
    
    Args:
        repo_url: GitHub repository URL
        token: GitHub token (optional)
        max_files: Maximum files to fetch
        skip_tests: Skip test files
        verbose: Print progress
    
    Returns:
        Dictionary of {filepath: content}
    """
    fetcher = GitHubFetcher(token=token, verbose=verbose)
    return fetcher.fetch_repository(repo_url, max_files, skip_tests)


if __name__ == "__main__":
    # Example usage
    print("GitHub Fetcher - Example Usage\n")
    from dotenv import load_dotenv
    load_dotenv(".env")
    
    # Test with a small public repository
    test_repo = "https://github.com/psf/requests"  # Famous Python library
    
    try:
        files = fetch_repo(
            test_repo,
            max_files=5,  # Limit for testing
            verbose=True,
            token=os.getenv("GITHUB_ACCESS_TOKEN") 
        )
        
        print(f"\n{'='*70}")
        print(f"Fetched Files:")
        print(f"{'='*70}")
        
        for filepath, content in files.items():
            lines = len(content.split('\n'))
            print(f"  {filepath} ({lines} lines)")
    
    except GitHubAPIError as e:
        print(f"❌ Error: {e}")