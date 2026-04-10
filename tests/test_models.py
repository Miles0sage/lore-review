from lore_review.models import ReviewRequest, Finding, CouncilVerdict, ReviewResult, ImmunityRule


def test_review_request():
    r = ReviewRequest(repo_path="/tmp/repo", pr_diff="--- a/foo.py\n+++ b/foo.py\n+x=1")
    assert r.pr_id == "local"


def test_finding_defaults():
    f = Finding(severity="high", category="security", message="SQL injection", file_path="db.py")
    assert f.confidence == 1.0
    assert f.graph_evidence == []


def test_council_verdict():
    v = CouncilVerdict(findings=[], consensus_score=0.9, cost_usd=0.01)
    assert v.immunity_rules_applied == 0


def test_immunity_rule():
    r = ImmunityRule(rule_id="abc", pattern="sql injection", category="security", confidence=0.8)
    assert r.times_applied == 0
