import pytest
from pathlib import Path
from lore_review.darwin_store import DarwinStore
from lore_review.models import Finding


@pytest.fixture
def store(tmp_path):
    return DarwinStore(db_path=tmp_path / "darwin.db")


def test_repo_id_deterministic(store):
    assert store.repo_id_from_path("/tmp/repo") == store.repo_id_from_path("/tmp/repo")


def test_get_rules_empty(store):
    assert store.get_rules("abc123") == []


def test_record_miss(store):
    f = Finding(severity="high", category="security", message="test vuln", file_path="x.py")
    store.record_miss("repo1", f, was_caught=False)


def test_compile_rules_threshold(store):
    f = Finding(severity="high", category="security", message="sql injection risk", file_path="db.py")
    # Need 2+ occurrences to compile
    store.record_miss("repo1", f, was_caught=False)
    store.record_miss("repo1", f, was_caught=False)
    rules = store.compile_rules("repo1")
    assert len(rules) >= 1
    assert rules[0].category == "security"


def test_compile_rules_below_threshold(store):
    f = Finding(severity="low", category="style", message="single occurrence", file_path="x.py")
    store.record_miss("repo1", f, was_caught=False)
    rules = store.compile_rules("repo1")
    assert len(rules) == 0
