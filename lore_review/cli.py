"""CLI: lore-review scan diff.patch | lore-review darwin list | lore-review suppress"""
import argparse
import json
import sys
import time
from pathlib import Path

from .darwin_store import DarwinStore
from .lore_config import LoreConfig
from .models import Finding, ReviewRequest
from .review_pipeline import review_pr
from .agents.scaffolder import scaffold_findings

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


def _severity_gte(severity: str, threshold: str) -> bool:
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return order.get(severity, 99) <= order.get(threshold, 99)


def _print_text(result, scaffolded=None):
    counts = {}
    for f in result.verdict.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    critical = counts.get("critical", 0)
    high = counts.get("high", 0)
    medium = counts.get("medium", 0)

    scaffold_map = {id(f): fix for f, fix in scaffolded} if scaffolded else {}

    w = 56
    print("━" * w)
    print(f"FINDINGS  ({len(result.verdict.findings)} total · "
          f"{critical} critical · {high} high · {medium} medium)")
    print("━" * w)
    for f in result.verdict.findings:
        print(f"\n[{f.severity.upper()}] {f.file_path}:{f.line_start}  {f.category}")
        print(f"  {f.message}")
        fix = scaffold_map.get(id(f))
        if fix:
            print(f"\n  ▶ FIX:")
            for line in fix.splitlines():
                print(f"    {line}")
    print("\n" + "━" * w)
    print(f"COST  ${result.total_cost_usd:.4f}  |  "
          f"Darwin rules applied: {result.verdict.immunity_rules_applied}  |  "
          f"New rules learned: {result.darwin_rules_learned}")
    print("━" * w)


def _print_sarif(result, tool_version: str = "0.4.1"):
    """Emit SARIF 2.1.0 — natively parsed by GitHub Code Scanning."""
    sev_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}
    rules: dict[str, dict] = {}
    sarif_results = []
    for f in result.verdict.findings:
        rule_id = f"LR-{f.category.upper()}-{f.severity.upper()}"
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f"{f.category.title()}Finding",
                "shortDescription": {"text": f"{f.category} finding ({f.severity})"},
                "defaultConfiguration": {"level": sev_map.get(f.severity, "warning")},
                "properties": {"tags": ["security", "lore-review", f.category]},
            }
        sarif_results.append({
            "ruleId": rule_id,
            "level": sev_map.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file_path or "unknown", "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": max(1, f.line_start or 1)},
                }
            }],
            "properties": {"confidence": f.confidence, "category": f.category},
        })
    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "lore-review",
                    "version": tool_version,
                    "informationUri": "https://github.com/Miles0sage/lore-review",
                    "rules": list(rules.values()),
                }
            },
            "results": sarif_results,
        }],
    }
    print(json.dumps(sarif, indent=2))


def _print_github(result):
    for f in result.verdict.findings:
        level = "error" if f.severity in ("critical", "high") else "warning"
        loc = f"file={f.file_path},line={f.line_start}"
        msg = f.message.replace("\n", "%0A").replace(",", "%2C")
        print(f"::{level} {loc}::[{f.severity.upper()}] {f.category}: {msg}")
    print(
        f"Lore Review complete — {len(result.verdict.findings)} findings "
        f"(cost: ${result.total_cost_usd:.4f})",
        file=sys.stderr,
    )


def _run_scan(diff_path, repo, pr_id, output_format, fail_on, store=None, scaffold=False, mode="full", strict=False):
    diff = sys.stdin.read() if diff_path == "-" else Path(diff_path).read_text()
    request = ReviewRequest(repo_path=repo, pr_diff=diff, pr_id=pr_id)
    result = review_pr(request, store=store, mode=mode, strict=strict)
    if strict:
        lore_path = Path(repo) / ".lore.yml"
        print(f"[strict mode] Only .lore.yml suppressions applied ({lore_path})", file=sys.stderr)

    scaffolded = None
    if scaffold and result.verdict.findings:
        scaffolded = scaffold_findings(result.verdict.findings, diff)

    if output_format == "json":
        if scaffolded:
            data = result.model_dump()
            fix_map = {id(f): fix for f, fix in scaffolded}
            for i, f in enumerate(result.verdict.findings):
                data["verdict"]["findings"][i]["fix_suggestion"] = fix_map.get(id(f), "")
        print(json.dumps(data if scaffolded else result.model_dump(), indent=2))
    elif output_format == "github":
        _print_github(result)
    elif output_format == "sarif":
        _print_sarif(result)
    else:
        _print_text(result, scaffolded=scaffolded)

    if fail_on != "never":
        for f in result.verdict.findings:
            if _severity_gte(f.severity, fail_on):
                sys.exit(1)


def _add_scan_args(p):
    p.add_argument("diff", nargs="?", default="-",
                   help="Diff file path or '-' for stdin (default: stdin)")
    p.add_argument("--pr-id", default="local")
    p.add_argument("--output", "--format", choices=["text", "json", "github", "sarif"],
                   default="text", dest="output", metavar="FORMAT",
                   help="Output format: text | json | github (default: text)")
    p.add_argument("--fail-on",
                   choices=["critical", "high", "medium", "low", "info", "never"],
                   default="critical",
                   help="Exit 1 if any finding >= this severity (default: critical)")
    p.add_argument("--scaffold", action="store_true",
                   help="Generate fix suggestions for each finding (paid tier preview)")
    p.add_argument("--mode", choices=["full", "security"],
                   default="full",
                   help="full: all 5 council workers | security: security+agent_security only (lower FP rate)")
    p.add_argument("--strict", action="store_true",
                   help="Strict mode: only apply suppressions from .lore.yml — ignore auto-learned Darwin rules (required for CI gating)")


def cmd_scan(args):
    _run_scan(args.diff, args.repo, args.pr_id, args.output, args.fail_on,
              scaffold=getattr(args, "scaffold", False),
              mode=getattr(args, "mode", "full"),
              strict=getattr(args, "strict", False))


def cmd_pr(args):
    """Review a GitHub PR by URL. Downloads the diff via GitHub API."""
    import urllib.request
    url = args.url
    # Parse owner/repo/pull number from URL
    parts = url.rstrip("/").split("/")
    try:
        pull_idx = parts.index("pull")
        owner, repo_name = parts[pull_idx - 2], parts[pull_idx - 1]
        pr_num = parts[pull_idx + 1]
    except (ValueError, IndexError):
        print(f"Could not parse GitHub PR URL: {url}", file=sys.stderr)
        sys.exit(1)

    api_url = f"https://api.github.com/repos/{owner}/{repo_name}/pulls/{pr_num}"
    req = urllib.request.Request(api_url, headers={"Accept": "application/vnd.github.v3.diff"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            diff = resp.read().decode()
    except Exception as e:
        print(f"Failed to fetch PR diff: {e}", file=sys.stderr)
        sys.exit(1)

    import tempfile, os
    with tempfile.NamedTemporaryFile(suffix=".diff", mode="w", delete=False) as f:
        f.write(diff)
        tmp = f.name
    try:
        _run_scan(tmp, args.repo or ".", f"pr-{pr_num}", args.output, args.fail_on)
    finally:
        os.unlink(tmp)


def cmd_darwin_list(args):
    store = DarwinStore(db_path=Path(args.db))
    repo_id = store.repo_id_from_path(str(Path(args.repo).resolve()))
    rules = store.get_rules(repo_id)
    if not rules:
        print("No immunity rules compiled yet for this repository.")
        print("Run lore-review scan on a few PRs, then suppress false positives.")
        return
    print(f"{'ID':<20} {'Pattern':<30} {'Confidence':>10} {'Applied':>8}")
    print("-" * 72)
    for r in rules:
        print(f"{r.rule_id[-16:]:<20} {r.pattern:<30} {r.confidence:>10.2f} {r.times_applied:>8}")


def cmd_darwin_export(args):
    store = DarwinStore(db_path=Path(args.db))
    repo_id = store.repo_id_from_path(str(Path(args.repo).resolve()))
    rules = store.get_rules(repo_id)
    print(json.dumps([r.model_dump() for r in rules], indent=2))


def cmd_darwin_import(args):
    store = DarwinStore(db_path=Path(args.db))
    import sqlite3
    with open(args.file) as f:
        rules = json.load(f)
    with sqlite3.connect(store._db) as conn:
        for r in rules:
            conn.execute(
                "INSERT OR REPLACE INTO immunity_rules VALUES (?,?,?,?,?,?)",
                (r["rule_id"], r["pattern"], r["category"],
                 r["confidence"], r["times_applied"], r.get("created_at", ""))
            )
    print(f"Imported {len(rules)} immunity rules.")


def cmd_suppress(args):
    """Manually suppress a bug type — writes to both Darwin DB and .lore.yml.

    .lore.yml entry is the auditable artifact for strict mode / CI gating.
    Commit .lore.yml alongside the suppression so reviewers can audit it.
    """
    import hashlib, sqlite3
    store = DarwinStore(db_path=Path(args.db))
    repo_id = store.repo_id_from_path(str(Path(args.repo).resolve()))
    pattern = args.bug_type
    rule_id = f"{repo_id}_{hashlib.sha256(pattern.encode()).hexdigest()[:8]}"
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ")
    with sqlite3.connect(store._db) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO immunity_rules VALUES (?,?,?,?,?,?)",
            (rule_id, pattern, args.category, 1.0, 1, created)
        )

    # Write to .lore.yml — the git-committable, PR-reviewable artifact
    lore_cfg = LoreConfig(args.repo)
    entry = lore_cfg.add_suppression(
        rule_id=pattern,          # use bug-type key as rule_id in .lore.yml (human-readable)
        file_pattern=getattr(args, "file_pattern", "*"),
        reason=args.reason or "(no reason provided)",
        code_snippet=getattr(args, "code_snippet", ""),
        approved_by=getattr(args, "approved_by", "cli"),
        category=args.category,
    )

    print(f"Added immunity rule: {pattern} ({args.category})")
    print(f"Rule ID (Darwin DB): {rule_id}")
    print(f".lore.yml entry written: {lore_cfg.path()}")
    if args.reason:
        print(f"Reason: {args.reason}")
    print()
    print("Next steps:")
    print(f"  git add {lore_cfg.path()} && git commit -m 'lore: suppress {pattern}'")
    print("  Reviewers can audit this suppression in the PR diff.")


def main():
    parser = argparse.ArgumentParser(
        prog="lore-review",
        description="Lore Review — AI code review that learns",
    )
    parser.add_argument("--db", default=".lore-review/darwin.db",
                        help="Darwin DB path (default: .lore-review/darwin.db)")
    parser.add_argument("--repo", default=".", help="Repository root (default: .)")

    subs = parser.add_subparsers(dest="command")

    def _add_repo_db(p):
        p.add_argument("--repo", default=".", help="Repository root (default: .)")
        p.add_argument("--db", default=".lore-review/darwin.db")

    # scan
    p_scan = subs.add_parser("scan", help="Review a diff file or stdin")
    _add_scan_args(p_scan)
    _add_repo_db(p_scan)

    # pr
    p_pr = subs.add_parser("pr", help="Review a GitHub PR by URL")
    p_pr.add_argument("url", help="GitHub PR URL")
    p_pr.add_argument("--output", "--format", choices=["text", "json", "github", "sarif"],
                      default="text", dest="output")
    p_pr.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info", "never"],
                      default="critical")
    _add_repo_db(p_pr)

    # darwin list/export/import
    p_darwin = subs.add_parser("darwin", help="Manage Darwin immunity rules")
    darwin_subs = p_darwin.add_subparsers(dest="darwin_cmd")
    for dp in [darwin_subs.add_parser("list"), darwin_subs.add_parser("export")]:
        _add_repo_db(dp)
    p_import = darwin_subs.add_parser("import", help="Import rules from JSON file")
    p_import.add_argument("file", help="JSON file to import")
    _add_repo_db(p_import)

    # suppress
    p_suppress = subs.add_parser("suppress", help="Manually suppress a bug type")
    p_suppress.add_argument("--bug-type", required=True,
                            help="Normalized bug type key (e.g. sql_injection, eval_exec)")
    p_suppress.add_argument("--category", default="security",
                            choices=["security", "performance", "correctness", "style", "agent_security"])
    p_suppress.add_argument("--reason", default="", help="Reason for suppression")
    p_suppress.add_argument("--file-pattern", default="*", dest="file_pattern",
                            help="Scope suppression to a path prefix (e.g. 'tests/') or '*' for repo-wide")
    p_suppress.add_argument("--approved-by", default="cli", dest="approved_by",
                            help="GitHub username or identifier of the approver")
    _add_repo_db(p_suppress)

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "pr":
        cmd_pr(args)
    elif args.command == "darwin":
        if args.darwin_cmd == "list":
            cmd_darwin_list(args)
        elif args.darwin_cmd == "export":
            cmd_darwin_export(args)
        elif args.darwin_cmd == "import":
            cmd_darwin_import(args)
        else:
            parser.parse_args(["darwin", "--help"])
    elif args.command == "suppress":
        cmd_suppress(args)
    else:
        # Legacy: if called without subcommand, check for --diff flag
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
