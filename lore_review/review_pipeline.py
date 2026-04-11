"""Main review pipeline: Scout → [Static + Council parallel] → Sentinel → Darwin."""
import concurrent.futures
from .models import ReviewRequest, ReviewResult, CouncilVerdict, Finding, ImmunityRule
from .darwin_store import DarwinStore
from .graph_reader import GraphReader
from .agents.scout import run_scout
from .agents.council import run_council
from .agents.sentinel import run_sentinel, _bug_type
from .agents.static_scan import run_static_scan


def _hard_suppress(
    findings: list[Finding], rules: list[ImmunityRule]
) -> tuple[list[Finding], int]:
    """Deterministically remove findings whose normalized bug_type matches a compiled immunity rule.

    This is a hard filter — no AI involved. Once Darwin compiles a rule (after 2+
    occurrences of the same bug_type being flagged and suppressed), that pattern
    is *never* surfaced again until the rule is manually revoked.
    """
    if not rules:
        return findings, 0
    rule_patterns = {r.pattern for r in rules}
    kept, suppressed = [], 0
    for f in findings:
        if _bug_type(f.message) in rule_patterns:
            suppressed += 1
        else:
            kept.append(f)
    return kept, suppressed


def review_pr(request: ReviewRequest, store: DarwinStore = None, graph_reader: GraphReader = None, mode: str = "full") -> ReviewResult:
    if store is None:
        store = DarwinStore()
    if graph_reader is None:
        graph_reader = GraphReader()

    repo_id = store.repo_id_from_path(request.repo_path)
    immunity_rules = store.get_rules(repo_id)

    scout_ctx = run_scout(request.pr_diff, request.repo_path, graph_reader)

    # Static scan (deterministic, zero AI cost) runs in parallel with Council
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        static_future = ex.submit(run_static_scan, request.pr_diff)
        council_future = ex.submit(run_council, scout_ctx, immunity_rules, False, mode)
        static_findings = static_future.result()
        verdict = council_future.result()

    # Merge static findings into verdict — Sentinel will dedup overlaps
    if static_findings:
        verdict = CouncilVerdict(
            findings=static_findings + list(verdict.findings),
            consensus_score=verdict.consensus_score,
            cost_usd=verdict.cost_usd,
            immunity_rules_applied=verdict.immunity_rules_applied,
        )

    verdict = run_sentinel(verdict, scout_ctx)

    # Hard suppression: deterministically drop findings matching compiled immunity rules.
    # This runs BEFORE recording — suppressed findings are not re-recorded as new misses.
    findings_after_darwin, suppressed_count = _hard_suppress(verdict.findings, immunity_rules)
    if suppressed_count:
        verdict = CouncilVerdict(
            findings=findings_after_darwin,
            consensus_score=verdict.consensus_score,
            cost_usd=verdict.cost_usd,
            immunity_rules_applied=suppressed_count,
        )

    # Record normalized bug-type patterns so Darwin can cluster across runs.
    # (raw messages vary between AI runs; bug-type key is stable)
    for finding in verdict.findings:
        normalized = Finding(
            severity=finding.severity,
            category=finding.category,
            message=_bug_type(finding.message),
            file_path=finding.file_path,
            line_start=finding.line_start,
        )
        store.record_miss(repo_id, normalized, was_caught=True)

    new_rules = store.compile_rules(repo_id)

    return ReviewResult(
        pr_id=request.pr_id,
        verdict=verdict,
        darwin_rules_learned=len(new_rules),
        total_cost_usd=verdict.cost_usd,
    )
