"""Scout — maps the territory before the review."""
from ..graph_reader import GraphReader


def run_scout(diff: str, repo_path: str, graph_reader: GraphReader) -> dict:
    context = graph_reader.get_pr_context(diff, repo_path)
    changed_files = context.get("changed_files", [])
    lines_changed = sum(1 for l in diff.splitlines() if l.startswith(("+", "-")) and not l.startswith(("+++", "---")))
    return {
        "diff": diff,
        "changed_files": changed_files,
        "lines_changed": lines_changed,
        "graph_context": context,
        "graph_available": context.get("graph_available", False),
        "risk_score": context.get("risk_score", 0.5),
    }
