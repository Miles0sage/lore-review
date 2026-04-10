"""Main review pipeline: Scout → Council → Sentinel → Darwin."""
from .models import ReviewRequest, ReviewResult
from .darwin_store import DarwinStore
from .graph_reader import GraphReader
from .agents.scout import run_scout
from .agents.council import run_council
from .agents.sentinel import run_sentinel


def review_pr(request: ReviewRequest, store: DarwinStore = None, graph_reader: GraphReader = None) -> ReviewResult:
    if store is None:
        store = DarwinStore()
    if graph_reader is None:
        graph_reader = GraphReader()

    repo_id = store.repo_id_from_path(request.repo_path)
    immunity_rules = store.get_rules(repo_id)

    scout_ctx = run_scout(request.pr_diff, request.repo_path, graph_reader)
    verdict = run_council(scout_ctx, immunity_rules)
    verdict = run_sentinel(verdict, scout_ctx)

    new_rules = store.compile_rules(repo_id)

    return ReviewResult(
        pr_id=request.pr_id,
        verdict=verdict,
        darwin_rules_learned=len(new_rules),
        total_cost_usd=verdict.cost_usd,
    )
