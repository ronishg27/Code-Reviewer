# Code-Reviewer

Automated code review tool that scans Python repositories for security vulnerabilities and code quality issues.

## How it works

1. Point it at any public GitHub repo
2. It fetches `.py` files via the GitHub REST API
3. Each file is analyzed by a set of AST-based detectors and metrics calculators

## Features

**Security detectors** — static analysis, no execution of target code
- SQL injection (context-aware, taint tracking through variables)
- Command injection (`os.system`, `subprocess`, `eval`/`exec`, etc.)
- Hardcoded secrets (API keys, tokens, passwords, JWT, AWS keys)
- Insecure deserialization (`pickle`, `yaml.load`, etc.)
- Weak random number generation
- Dangerous function usage (`assert`, `eval`, `exec`, `__import__`)
- Context-aware taint propagation (tracks input → transformation → sink)

**Code quality detectors**
- Bare `except` clauses
- Deeply nested code (>5 levels)
- Overly long functions (>50 lines)

**Code metrics**
- Cyclomatic and cognitive complexity
- Lines of code (physical and logical)
- Maintainability Index
- Nesting depth, parameter count, return count

## Quick start

```powershell
pip install -r requirements.txt
copy .env.sample .env
```

Edit `.env` and add your [GitHub personal access token](https://github.com/settings/tokens) (required for API access):

```
GITHUB_ACCESS_TOKEN="ghp_..."
```

Run the server:

```powershell
python src\app.py
```

## Usage

### Web API

```powershell
curl -X POST http://localhost:5000/analyze ^
  -H "Content-Type: application/json" ^
  -d "{\"github_url\": \"https://github.com/psf/requests\", \"max_files\": 10}"
```

**Request fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `github_url` | string | — | Full GitHub repo URL (required) |
| `max_files` | number | 100 | Limit number of files to scan |
| `skip_tests` | bool | true | Skip test files |

**Response** includes a summary by severity, top issues, per-file results with metrics, and any fetch errors.

### Programmatic usage

```python
from src.core.repo_analyzer import analyze_repo

result = analyze_repo(
    repo_url="https://github.com/psf/requests",
    max_files=10,
    verbose=True
)

print(f"Total issues: {result.total_issues}")
result.save_report("report.json")
```

Or scan local code directly:

```python
from src.scanner import scan_code

result = scan_code('''
import os
os.system("ls")
''', "example.py")

result.print_report(verbose=True)
```

## Tests

```powershell
pytest
```

Most tests also run standalone:

```powershell
python src\tests\test_scanner.py
python src\tests\test_context_aware.py
```

Integration tests (`test_github_integration.py`) call the live GitHub API and require a token in `.env`.

## Project structure

```
src/
  app.py                         # Flask web server (POST /analyze)
  scanner.py                     # SecurityScanner — orchestrates all detectors
  core/
    github_fetcher.py            # GitHub REST API client
    repo_analyzer.py             # Fetches + scans an entire repo
  analyzers/
    security/                    # AST-based security detectors
      base.py                    # BaseDetector, taint tracking, import resolution
      sql_injection_detector.py
      command_injection_detector.py
      hardcoded_secrets_detector.py
      insecure_deserialization_detector.py
      weak_random_detector.py
      assert_detector.py
      dangerous_functions.py
    smells/                      # Code smell detectors
      bare_except_detector.py
      deep_nesting_detector.py
      long_function_detector.py
    metrics/                     # Code metrics calculators
      base.py
      complexity.py
      code_stats.py
      maintainability.py
  models/
    issue_model.py               # Issue dataclass
  utils/
    get_function_name.py         # AST utility for extracting function names
  tests/                         # All test files
```

## License

MIT
