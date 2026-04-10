from lore_review.models import ReviewRequest
from lore_review.review_pipeline import review_pr
from lore_review.darwin_store import DarwinStore
from lore_review.graph_reader import GraphReader


def test_pipeline_no_graph(tmp_path):
    store = DarwinStore(db_path=tmp_path / "darwin.db")
    graph = GraphReader(mcp_url="http://localhost:9999")  # won't connect
    req = ReviewRequest(
        repo_path=str(tmp_path),
        pr_diff="--- a/foo.py\n+++ b/foo.py\n@@ -1 +1 @@\n-old\n+new",
        pr_id="test-pr-1"
    )
    result = review_pr(req, store=store, graph_reader=graph)
    assert result.pr_id == "test-pr-1"
    assert result.total_cost_usd >= 0
    assert result.darwin_rules_learned == 0


def test_pipeline_result_structure(tmp_path):
    store = DarwinStore(db_path=tmp_path / "darwin.db")
    req = ReviewRequest(repo_path=str(tmp_path), pr_diff="", pr_id="pr-2")
    result = review_pr(req, store=store)
    assert hasattr(result, 'verdict')
    assert hasattr(result.verdict, 'findings')
