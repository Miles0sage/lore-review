"""Test Darwin hard suppression — deterministic filter, not prompt-hinting."""
import sqlite3
import time
import pytest
from lore_review.models import Finding, ImmunityRule, CouncilVerdict
from lore_review.review_pipeline import _hard_suppress
from lore_review.darwin_store import DarwinStore
from lore_review.agents.sentinel import _bug_type


def _finding(msg, severity="high", category="security", file="app.py", line=10):
    return Finding(severity=severity, category=category, message=msg,
                   file_path=file, line_start=line)


def _rule(pattern, category="security"):
    return ImmunityRule(rule_id=f"repo_{pattern}", pattern=pattern,
                        category=category, confidence=0.9, times_applied=3)


class TestHardSuppress:
    def test_no_rules_returns_all(self):
        findings = [_finding("sql injection via f-string"), _finding("eval on user input")]
        kept, suppressed = _hard_suppress(findings, [])
        assert kept == findings
        assert suppressed == 0

    def test_matching_rule_removes_finding(self):
        findings = [_finding("SQL injection: f-string interpolation")]
        rules = [_rule("sql_injection")]
        kept, suppressed = _hard_suppress(findings, rules)
        assert suppressed == 1
        assert len(kept) == 0

    def test_non_matching_rule_keeps_finding(self):
        findings = [_finding("SQL injection: f-string interpolation")]
        rules = [_rule("cmd_injection")]  # different bug type
        kept, suppressed = _hard_suppress(findings, rules)
        assert suppressed == 0
        assert len(kept) == 1

    def test_mixed_findings_partial_suppress(self):
        findings = [
            _finding("sql injection via f-string"),      # → sql_injection
            _finding("eval() on untrusted user input"),  # → eval_exec
            _finding("O(n^2) nested loop quadratic"),    # → quadratic
        ]
        rules = [_rule("sql_injection")]
        kept, suppressed = _hard_suppress(findings, rules)
        assert suppressed == 1
        assert len(kept) == 2
        msgs = [f.message for f in kept]
        assert not any("sql" in m.lower() for m in msgs)

    def test_multiple_rules_suppress_multiple(self):
        findings = [
            _finding("sql injection via f-string"),
            _finding("command injection shell=True"),
            _finding("hardcoded API key in source"),
        ]
        rules = [_rule("sql_injection"), _rule("cmd_injection"), _rule("hardcoded_secret")]
        kept, suppressed = _hard_suppress(findings, rules)
        assert suppressed == 3
        assert kept == []

    def test_suppression_is_deterministic(self):
        """Same inputs always produce same outputs — no AI, no randomness."""
        findings = [_finding("sql injection via f-string")]
        rules = [_rule("sql_injection")]
        results = [_hard_suppress(findings, rules) for _ in range(5)]
        counts = [r[1] for r in results]
        assert all(c == 1 for c in counts)


class TestDarwinLearningLoop:
    def test_rules_compile_after_threshold(self, tmp_path):
        """After 2+ occurrences of same bug_type, Darwin compiles an immunity rule."""
        store = DarwinStore(db_path=tmp_path / "darwin.db")
        repo_id = "testrepo"
        f = _finding("sql injection via f-string")

        # First occurrence — below threshold, no rule yet
        store.record_miss(repo_id, Finding(severity="high", category="security",
                                           message="sql_injection", file_path="a.py", line_start=1), True)
        rules = store.compile_rules(repo_id)
        assert len(rules) == 0  # only 1 occurrence

        # Second occurrence — threshold hit, rule compiled
        store.record_miss(repo_id, Finding(severity="high", category="security",
                                           message="sql_injection", file_path="b.py", line_start=5), True)
        rules = store.compile_rules(repo_id)
        assert len(rules) == 1
        assert rules[0].pattern == "sql_injection"

    def test_compiled_rule_suppresses_future_findings(self, tmp_path):
        """Full loop: record → compile → hard suppress."""
        store = DarwinStore(db_path=tmp_path / "darwin.db")
        repo_id = "testrepo"
        bug_msg = "sql_injection"  # normalized key

        # Seed two occurrences to hit compile threshold
        for _ in range(2):
            store.record_miss(repo_id, Finding(severity="high", category="security",
                                               message=bug_msg, file_path="x.py", line_start=1), True)
        rules = store.compile_rules(repo_id)
        assert len(rules) == 1

        # Now a new finding with the same bug_type is hard-suppressed
        findings = [_finding("SQL injection: user input directly in f-string")]
        kept, suppressed = _hard_suppress(findings, rules)
        assert suppressed == 1
        assert kept == []

    def test_different_repos_isolated(self, tmp_path):
        """Rules from repo A don't leak to repo B."""
        store = DarwinStore(db_path=tmp_path / "darwin.db")
        repo_a = "aaaa"
        repo_b = "bbbb"

        for _ in range(2):
            store.record_miss(repo_a, Finding(severity="high", category="security",
                                               message="sql_injection", file_path="a.py", line_start=1), True)
        store.compile_rules(repo_a)

        rules_b = store.get_rules(repo_b)
        assert rules_b == []  # repo B has no rules
