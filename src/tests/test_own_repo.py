# test_my_repo.py
"""Test analyzing your own repository."""


from src.core.repo_analyzer import analyze_repo

# Analyze your code-reviewer repository
result = analyze_repo(
    repo_url="https://github.com/ronishg27/code-reviewer",
    max_files=999999,  # Adjust based on your repo size
    skip_tests=True,
    verbose=True
)

# Print summary
print("\n" + "="*70)
print("ANALYSIS COMPLETE!")
print("="*70)
result.print_summary(verbose=True)

# Save JSON report
output_file = "my_repo_analysis.json"
result.save_report(output_file)

print(f"\n📄 Full JSON report saved to: {output_file}")
print("\nTo view JSON:")
print(f"  cat {output_file}")
print(f"  # or")
print(f"  python -m json.tool {output_file}")