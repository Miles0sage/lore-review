"""MCP server for lore-review — expose AI code security scanning as MCP tools."""
from __future__ import annotations

import json
import traceback
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("lore-review")


def _findings_to_json(findings) -> list[dict]:
    return [
        {
            "severity": f.severity,
            "category": f.category,
            "message": f.message,
            "file_path": f.file_path,
            "line_start": f.line_start,
            "confidence": f.confidence,
        }
        for f in findings
    ]


@mcp.tool()
def lore_scan(diff: str, mode: str = "security", strict: bool = False) -> str:
    """Scan a git diff for AI-agent-specific security vulnerabilities.

    Uses the full review pipeline: scout -> static + council -> sentinel -> darwin.

    Args:
        diff: Git diff string to scan.
        mode: "security" (default) or "full" — controls which categories to report.
        strict: If true, only apply explicit .lore.yml suppressions (not auto-learned Darwin rules).
    """
    try:
        from .models import ReviewRequest
        from .review_pipeline import review_pr

        req = ReviewRequest(repo_path=".", pr_diff=diff, pr_id="mcp")
        result = review_pr(req, strict=strict)
        findings = result.verdict.findings

        if mode == "security":
            findings = [f for f in findings if f.category in ("security", "agent_security", "static")]

        return json.dumps({
            "findings": _findings_to_json(findings),
            "total": len(findings),
            "cost_usd": result.total_cost_usd,
            "darwin_rules_learned": result.darwin_rules_learned,
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


@mcp.tool()
def lore_scan_quick(diff: str) -> str:
    """Quick static-only scan — zero AI cost, instant results.

    Checks for 22 deterministic vulnerability patterns including eval/exec chains,
    pickle deserialization, prompt injection, SSRF, and more. No API calls needed.

    Args:
        diff: Git diff string to scan.
    """
    try:
        from .agents.static_scan import run_static_scan

        findings = run_static_scan(diff)
        return json.dumps({
            "findings": _findings_to_json(findings),
            "total": len(findings),
            "cost_usd": 0.0,
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


@mcp.tool()
def lore_suppress(rule_id: str, file_pattern: str = "*", reason: str = "", repo_path: str = ".") -> str:
    """Add an explicit suppression rule to .lore.yml.

    Suppressions are git-committed, PR-reviewable artifacts. Use when a finding
    is a confirmed false positive.

    Args:
        rule_id: Bug type key to suppress (e.g. eval_exec, pickle_load).
        file_pattern: Path prefix or '*' for repo-wide (e.g. 'tests/').
        reason: Why this is a false positive.
        repo_path: Repository root path.
    """
    try:
        from .lore_config import LoreConfig

        cfg = LoreConfig(repo_root=repo_path)
        entry = cfg.add_suppression(rule_id=rule_id, file_pattern=file_pattern, reason=reason)
        return json.dumps({
            "status": "ok",
            "message": f"Suppression added for '{rule_id}' on '{file_pattern}'",
            "lore_yml_path": str(cfg.path()),
            "entry": entry,
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


@mcp.tool()
def lore_darwin_list(repo_path: str = ".") -> str:
    """List all Darwin immunity rules for a repository.

    Darwin rules are auto-learned from repeated false positives. They reduce noise
    over time as the system learns your codebase patterns.

    Args:
        repo_path: Repository root path.
    """
    try:
        from .darwin_store import DarwinStore

        store = DarwinStore()
        repo_id = store.repo_id_from_path(repo_path)
        rules = store.get_rules(repo_id)
        return json.dumps({
            "rules": [
                {
                    "rule_id": r.rule_id,
                    "pattern": r.pattern,
                    "category": r.category,
                    "confidence": r.confidence,
                    "times_applied": r.times_applied,
                    "created_at": r.created_at,
                }
                for r in rules
            ],
            "total": len(rules),
            "repo_id": repo_id,
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e), "traceback": traceback.format_exc()})


def main():
    """Run the MCP server via stdio transport."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
