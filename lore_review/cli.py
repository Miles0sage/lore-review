"""CLI: lore-review --repo /path --diff patch.diff"""
import argparse
import sys
from pathlib import Path
from .models import ReviewRequest
from .review_pipeline import review_pr

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _severity_gte(severity: str, threshold: str) -> bool:
    """Return True if severity is >= threshold (more severe or equal)."""
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return order.get(severity, 99) <= order.get(threshold, 99)


def main():
    parser = argparse.ArgumentParser(description="Lore Review — AI code review that learns")
    parser.add_argument("--repo", required=True, help="Path to repository")
    parser.add_argument("--diff", required=True, help="Path to diff file or '-' for stdin")
    parser.add_argument("--pr-id", default="local")
    parser.add_argument("--output", choices=["text", "json", "github"], default="text")
    parser.add_argument(
        "--format",
        choices=["text", "json", "github"],
        dest="format_",
        default=None,
        help="Output format (alias for --output; github emits ::error:: annotations)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "info", "never"],
        default="critical",
        help="Exit code 1 if any finding meets or exceeds this severity (default: critical)",
    )
    args = parser.parse_args()

    # --format overrides --output when provided
    output_format = args.format_ if args.format_ is not None else args.output

    diff = sys.stdin.read() if args.diff == "-" else Path(args.diff).read_text()
    request = ReviewRequest(repo_path=args.repo, pr_diff=diff, pr_id=args.pr_id)
    result = review_pr(request)

    if output_format == "json":
        print(result.model_dump_json(indent=2))
    elif output_format == "github":
        # Emit GitHub Actions annotations
        for f in result.verdict.findings:
            level = "error" if f.severity in ("critical", "high") else "warning"
            loc = f"file={f.file_path},line={f.line_start}"
            msg = f.message.replace("\n", "%0A").replace(",", "%2C")
            print(f"::{level} {loc}::[{f.severity.upper()}] {f.category}: {msg}")
        # Summary to stderr so stdout stays clean for annotation parsing
        print(
            f"Lore Review complete — {len(result.verdict.findings)} findings "
            f"(cost: ${result.total_cost_usd:.4f})",
            file=sys.stderr,
        )
    else:
        print(f"Lore Review — PR {result.pr_id}")
        print(f"Findings: {len(result.verdict.findings)}")
        print(f"Darwin rules learned: {result.darwin_rules_learned}")
        print(f"Cost: ${result.total_cost_usd:.4f}")
        for f in result.verdict.findings:
            print(f"  [{f.severity.upper()}] {f.category}: {f.message} ({f.file_path}:{f.line_start})")

    # Exit code: 1 if any finding meets or exceeds --fail-on threshold
    if args.fail_on != "never":
        for f in result.verdict.findings:
            if _severity_gte(f.severity, args.fail_on):
                sys.exit(1)


if __name__ == "__main__":
    main()
