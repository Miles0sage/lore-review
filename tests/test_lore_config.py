"""Tests for LoreConfig — .lore.yml suppression hardening."""
import tempfile
from pathlib import Path
import pytest
from lore_review.lore_config import LoreConfig, _parse_lore_yml, _dump_lore_yml


@pytest.fixture
def tmp_repo(tmp_path):
    return tmp_path


def test_empty_config_no_suppressions(tmp_repo):
    cfg = LoreConfig(tmp_repo)
    assert cfg.get_suppressions() == []
    assert not cfg.has_any()


def test_add_suppression_creates_file(tmp_repo):
    cfg = LoreConfig(tmp_repo)
    cfg.add_suppression(
        rule_id="eval_exec",
        file_pattern="tests/",
        reason="Only used in test harness with safe literals",
        approved_by="miles",
        category="security",
    )
    lore_path = tmp_repo / ".lore.yml"
    assert lore_path.exists()
    content = lore_path.read_text()
    assert "eval_exec" in content
    assert "tests/" in content
    assert "Only used in test harness" in content
    assert "miles" in content


def test_add_suppression_persists_and_reloads(tmp_repo):
    cfg = LoreConfig(tmp_repo)
    cfg.add_suppression(rule_id="pickle_load", file_pattern="*", reason="Legacy compat")

    # Reload from disk
    cfg2 = LoreConfig(tmp_repo)
    sups = cfg2.get_suppressions()
    assert len(sups) == 1
    assert sups[0]["rule_id"] == "pickle_load"
    assert sups[0]["reason"] == "Legacy compat"


def test_multiple_suppressions(tmp_repo):
    cfg = LoreConfig(tmp_repo)
    cfg.add_suppression(rule_id="eval_exec", file_pattern="tests/", reason="Test only")
    cfg.add_suppression(rule_id="hardcoded_secret", file_pattern="config/", reason="Dev defaults")

    cfg2 = LoreConfig(tmp_repo)
    sups = cfg2.get_suppressions()
    assert len(sups) == 2
    rule_ids = {s["rule_id"] for s in sups}
    assert "eval_exec" in rule_ids
    assert "hardcoded_secret" in rule_ids


def test_is_suppressed_exact_match(tmp_repo):
    cfg = LoreConfig(tmp_repo)
    cfg.add_suppression(rule_id="eval_exec", file_pattern="tests/", reason="Safe")

    assert cfg.is_suppressed("eval_exec", "tests/test_foo.py")
    assert not cfg.is_suppressed("eval_exec", "src/main.py")  # wrong file prefix
    assert not cfg.is_suppressed("pickle_load", "tests/test_foo.py")  # wrong rule


def test_is_suppressed_wildcard_file(tmp_repo):
    cfg = LoreConfig(tmp_repo)
    cfg.add_suppression(rule_id="os_system_fstring", file_pattern="*", reason="Reviewed")

    assert cfg.is_suppressed("os_system_fstring", "any/path/here.py")
    assert cfg.is_suppressed("os_system_fstring", "")


def test_is_suppressed_code_hash_match(tmp_repo):
    cfg = LoreConfig(tmp_repo)
    code = "os.system(f'echo {user_input}')"
    cfg.add_suppression(
        rule_id="os_system_fstring",
        file_pattern="*",
        reason="Sandboxed",
        code_snippet=code,
    )

    assert cfg.is_suppressed("os_system_fstring", "any.py", code)
    assert not cfg.is_suppressed("os_system_fstring", "any.py", "different code")


def test_is_suppressed_no_hash_is_wildcard(tmp_repo):
    """Suppression with no code_hash matches any code snippet."""
    cfg = LoreConfig(tmp_repo)
    cfg.add_suppression(rule_id="tool_poisoning", file_pattern="*", reason="Reviewed")

    assert cfg.is_suppressed("tool_poisoning", "src/dispatch.py", "getattr(obj, user_input)()")
    assert cfg.is_suppressed("tool_poisoning", "src/other.py", "totally different code")


def test_roundtrip_serialisation(tmp_repo):
    """Dump and re-parse produces identical suppressions."""
    cfg = LoreConfig(tmp_repo)
    cfg.add_suppression(rule_id="prompt_injection", file_pattern="agents/", reason="Template only", approved_by="alice")
    cfg.add_suppression(rule_id="unbounded_loop", file_pattern="*", reason="Has break")

    cfg2 = LoreConfig(tmp_repo)
    s1 = cfg.get_suppressions()
    s2 = cfg2.get_suppressions()
    assert len(s1) == len(s2)
    for a, b in zip(s1, s2):
        assert a["rule_id"] == b["rule_id"]
        assert a["file_pattern"] == b["file_pattern"]
        assert a["reason"] == b["reason"]


def test_lore_yml_comment_header(tmp_repo):
    """The generated file should have audit guidance comments."""
    cfg = LoreConfig(tmp_repo)
    cfg.add_suppression(rule_id="eval_exec", file_pattern="*", reason="x")
    content = (tmp_repo / ".lore.yml").read_text()
    assert "reviewable artifact" in content
    assert "Commit this file" in content


def test_parse_yml_handles_empty():
    assert _parse_lore_yml("") == {}
    assert _parse_lore_yml("# just comments\n") == {}


def test_parse_yml_no_suppressions():
    data = _parse_lore_yml("version: 1\n")
    assert data.get("version") == "1"
    assert "suppressions" not in data


def test_hard_suppress_strict_ignores_autolearned():
    """In strict mode, auto-learned Darwin rules should NOT suppress findings."""
    from lore_review.models import Finding, ImmunityRule
    from lore_review.review_pipeline import _hard_suppress

    findings = [
        Finding(severity="high", category="security", message="eval() called with non-literal", file_path="src/x.py"),
    ]
    auto_rule = ImmunityRule(rule_id="abc_eval", pattern="eval_exec", category="security",
                              confidence=0.9, times_applied=3)

    with tempfile.TemporaryDirectory() as tmp:
        lore_cfg = LoreConfig(tmp)  # empty .lore.yml
        kept, suppressed = _hard_suppress(findings, [auto_rule], lore_cfg=lore_cfg, strict=True)

    assert suppressed == 0  # auto rule NOT applied in strict mode
    assert len(kept) == 1


def test_hard_suppress_strict_applies_lore_yml():
    """In strict mode, .lore.yml suppressions ARE applied."""
    from lore_review.models import Finding
    from lore_review.review_pipeline import _hard_suppress
    # _bug_type("eval() called with non-literal") -> "eval_called_with_nonliteral"

    findings = [
        Finding(severity="medium", category="security", message="eval() called with non-literal", file_path="tests/x.py"),
    ]

    with tempfile.TemporaryDirectory() as tmp:
        lore_cfg = LoreConfig(tmp)
        lore_cfg.add_suppression(rule_id="eval_called_with_nonliteral", file_pattern="tests/", reason="Safe in tests")
        kept, suppressed = _hard_suppress(findings, [], lore_cfg=lore_cfg, strict=True)

    assert suppressed == 1
    assert len(kept) == 0


def test_hard_suppress_nonstrict_applies_both():
    """In non-strict mode, both auto-learned and .lore.yml rules apply."""
    from lore_review.models import Finding, ImmunityRule
    from lore_review.review_pipeline import _hard_suppress
    # _bug_type("eval() called with non-literal") -> "eval_called_with_nonliteral"
    # _bug_type("pickle_load deserialization risk") -> "insecure_deserialization"

    findings = [
        Finding(severity="high", category="security", message="eval() called with non-literal", file_path="a.py"),
        Finding(severity="high", category="security", message="pickle_load deserialization risk", file_path="b.py"),
    ]
    auto_rule = ImmunityRule(rule_id="abc_eval", pattern="eval_called_with_nonliteral", category="security",
                              confidence=0.9, times_applied=3)

    with tempfile.TemporaryDirectory() as tmp:
        lore_cfg = LoreConfig(tmp)
        lore_cfg.add_suppression(rule_id="insecure_deserialization", file_pattern="*", reason="Reviewed")
        kept, suppressed = _hard_suppress(findings, [auto_rule], lore_cfg=lore_cfg, strict=False)

    assert suppressed == 2  # both rules applied
    assert len(kept) == 0
