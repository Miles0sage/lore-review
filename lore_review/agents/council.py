"""Council — 4 specialist reviewers debate the PR."""
from ..models import Finding, CouncilVerdict

COUNCIL_ROLES = {
    "security": "You are a security expert. Find injection, auth bypass, secrets exposure, OWASP Top 10 issues.",
    "performance": "You are a performance engineer. Find N+1 queries, blocking I/O, memory leaks, inefficient algorithms.",
    "correctness": "You are a correctness reviewer. Find logic errors, edge cases, null dereferences, race conditions.",
    "style": "You are a code quality reviewer. Find code smells, dead code, overly complex patterns, missing error handling.",
}


def run_council(scout_context: dict, immunity_rules: list, dry_run: bool = False) -> CouncilVerdict:
    """Run 4 specialist reviews. In dry_run mode returns empty verdict."""
    if dry_run or not scout_context.get("diff"):
        return CouncilVerdict(findings=[], consensus_score=1.0, cost_usd=0.0, immunity_rules_applied=len(immunity_rules))

    # In production: dispatch to AI Factory workers in parallel
    # For now: return structured placeholder that real workers will replace
    findings = []
    return CouncilVerdict(
        findings=findings,
        consensus_score=0.8,
        cost_usd=0.01,
        immunity_rules_applied=len(immunity_rules)
    )
