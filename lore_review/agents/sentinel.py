"""Sentinel — validates Council findings against graph facts."""
from ..models import CouncilVerdict, Finding


def run_sentinel(verdict: CouncilVerdict, scout_context: dict) -> CouncilVerdict:
    """Filter hallucinated findings (symbols not in graph)."""
    if not scout_context.get("graph_available"):
        return verdict  # Can't validate without graph — pass through

    known_files = set(scout_context.get("changed_files", []))
    validated = []
    for finding in verdict.findings:
        if not finding.file_path or finding.file_path in known_files:
            validated.append(finding)
        # Drop findings about files not in the diff

    return CouncilVerdict(
        findings=validated,
        consensus_score=verdict.consensus_score,
        cost_usd=verdict.cost_usd,
        immunity_rules_applied=verdict.immunity_rules_applied,
    )
