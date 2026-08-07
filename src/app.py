import os

from flask import Flask, request, jsonify
from urllib.parse import urlparse
import traceback

from src.core.repo_analyzer import analyze_repo
from src.core.github_fetcher import GitHubAPIError

app = Flask(__name__)


@app.route("/")
def home():
    return "Hello, World!!"


@app.route("/analyze", methods=["POST"])
def review():
    """
    Analyze a GitHub repository for security and code quality issues.
    
    Expected JSON:
    {
        "github_url": "https://github.com/owner/repo",
        "max_files": 100,  # optional
        "skip_tests": true  # optional
    }
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Request body must be JSON", "ok": False}), 400
        
        github_url = data.get("github_url", "").strip()
        max_files = data.get("max_files", 100)
        skip_tests = data.get("skip_tests", True)
        
        # URL validation
        url = urlparse(github_url)
        if url.scheme not in ("http", "https") or url.netloc != "github.com":
            return jsonify({
                "error": "Invalid GitHub repository URL", 
                "ok": False
            }), 400 
        
        path_parts = url.path.strip("/").split("/")
        if len(path_parts) < 2:
            return jsonify({
                "error": "Invalid GitHub repository URL", 
                "ok": False
            }), 400
        
        username = path_parts[0]
        repository = path_parts[1]
        
        print(f"Received GitHub URL: {github_url}")
        print(f"Extracted Username: {username}, Repository: {repository}")
        print(f"Options: max_files={max_files}, skip_tests={skip_tests}")
        
        # Run the analysis
        print(f"Starting analysis...")
        result = analyze_repo(
            repo_url=github_url,
            max_files=max_files,
            skip_tests=skip_tests,
            verbose=True,
            github_token=os.getenv("GITHUB_ACCESS_TOKEN")
        )
        
        # Get the summary
        summary = result.get_summary()
        top_issues = result.get_top_issues(limit=20)
        
        return jsonify({
            "github_url": github_url,
            "ok": True,
            "analysis": {
                "summary": summary,
                "top_issues": top_issues,
                "files_analyzed": result.scanned_files,
                "total_files_found": result.total_files,
                "fetch_errors": result.fetch_errors
            }
        }), 200
    
    except GitHubAPIError as e:
        print(f"GitHub API Error: {e}")
        return jsonify({
            "error": f"GitHub API error: {str(e)}", 
            "ok": False
        }), 400
    
    except Exception as e:
        print(f"Unexpected error: {e}")
        print(traceback.format_exc())
        return jsonify({
            "error": f"Internal server error: {str(e)}", 
            "ok": False
        }), 500


if __name__ == "__main__":
    app.run(debug=True)
