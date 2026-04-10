"""CLI: lore-review --repo /path --diff patch.diff"""
import argparse
import json
import sys
from pathlib import Path
from .models import ReviewRequest
from .review_pipeline import review_pr


def main():
    parser = argparse.ArgumentParser(description="Lore Review — AI code review that learns")
    parser.add_argument("--repo", required=True, help="Path to repository")
    parser.add_argument("--diff", required=True, help="Path to diff file or '-' for stdin")
    parser.add_argument("--pr-id", default="local")
    parser.add_argument("--output", choices=["text", "json"], default="text")
    args = parser.parse_args()

    diff = sys.stdin.read() if args.diff == "-" else Path(args.diff).read_text()
    request = ReviewRequest(repo_path=args.repo, pr_diff=diff, pr_id=args.pr_id)
    result = review_pr(request)

    if args.output == "json":
        print(result.model_dump_json(indent=2))
    else:
        print(f"Lore Review — PR {result.pr_id}")
        print(f"Findings: {len(result.verdict.findings)}")
        print(f"Darwin rules learned: {result.darwin_rules_learned}")
        print(f"Cost: ${result.total_cost_usd:.4f}")
        for f in result.verdict.findings:
            print(f"  [{f.severity.upper()}] {f.category}: {f.message} ({f.file_path}:{f.line_start})")


if __name__ == "__main__":
    main()
