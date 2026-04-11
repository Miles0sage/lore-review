"""Sentinel — validates Council findings, deduplicates cross-worker noise."""
from __future__ import annotations

import re
from ..models import CouncilVerdict, Finding

_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

# Bug-type keywords → canonical label for dedup
_BUG_PATTERNS = [
    (r"sql.inject|interpolat.*sql|parameteriz", "sql_injection"),
    (r"command.inject|shell=true|shell inject", "cmd_injection"),
    (r"hardcod|api.key|secret.*expos|expos.*secret|hardcoded.credential", "hardcoded_secret"),
    (r"\beval\b.*untrust|arbitrary.*exec|remote.*code|eval.*chain|exec.*non.literal", "eval_exec"),
    (r"o\(n.2\)|nested.loop|quadratic|n\^2", "quadratic"),
    (r"resource.leak|connection.*clos|conn\.close", "resource_leak"),
    (r"infinite.loop|no.exit|while true|unbounded.*agent|no.*max.iter", "infinite_loop"),
    (r"timeout|urlopen.*timeout", "missing_timeout"),
    (r"logic.error|duplicate.*mult|find_dup", "logic_error"),
    (r"pickle|deserializ|yaml\.load", "insecure_deserialization"),
    (r"timing.attack|compare_digest|constant.time", "timing_attack"),
    (r"race.condition|thread.*lock|global.*hit", "race_condition"),
    (r"path.traversal|directory.traversal|open.*user.controlled", "path_traversal"),
    (r"weak.*prng|random.*token|md5.*token", "weak_prng"),
    (r"unbounded.*thread|thread.*pool", "unbounded_threads"),
    (r"mutable.*default|default.*arg.*list", "mutable_default"),
    (r"redos|catastrophic.backtrack", "redos"),
    # AI agent-specific patterns
    (r"tool.poison|getattr.*user|dynamic.*dispatch.*user", "tool_poisoning"),
    (r"prompt.inject|user.*input.*prompt|llm.*prompt.*concat", "prompt_injection"),
    (r"pipe.to.interpret|curl.*python|wget.*bash|pipe.*exec", "pipe_to_interpreter"),
    (r"homograph|idn.*url|cyrillic.*url|lookalike.*domain", "homograph_url"),
    (r"ansi.*inject|terminal.*inject|escape.*seq|osc.*seq", "ansi_injection"),
    (r"cost.attack|token.*exhaust|runaway.*api|unbounded.*llm", "llm_cost_attack"),
    (r"ambient.*author|least.*privilege.*tool|overscop", "ambient_authority"),
    (r"memory.*poison|context.*poison|agent.*memory.*untrust", "memory_poisoning"),
    (r"callback.*inject|webhook.*user|url.*callback.*user", "callback_injection"),
    (r"__import__.*dynamic|importlib.*variable|dynamic.*module", "dynamic_import"),
]


def _bug_type(msg: str) -> str:
    lower = msg.lower()
    for pattern, label in _BUG_PATTERNS:
        if re.search(pattern, lower):
            return label
    # fallback: first 5 significant words
    words = re.sub(r"[^a-z\s]", "", lower).split()
    return "_".join(words[:5])


def _fingerprint(finding: Finding) -> str:
    """Stable key: file + 10-line bucket + bug type. Collapses cross-worker duplicates."""
    file_key = (finding.file_path or "").split("/")[-1]  # basename only
    line_bucket = ((finding.line_start or 0) // 10) * 10
    bug = _bug_type(finding.message)
    return f"{file_key}:{line_bucket}:{bug}"


def _dedup(findings: list[Finding]) -> list[Finding]:
    """Keep one finding per (file, line-bucket, bug-type), highest severity wins."""
    best: dict[str, Finding] = {}
    for f in findings:
        key = _fingerprint(f)
        current = best.get(key)
        if current is None or _SEV_RANK.get(f.severity.lower(), 0) > _SEV_RANK.get(current.severity.lower(), 0):
            best[key] = f
    return sorted(best.values(), key=lambda f: _SEV_RANK.get(f.severity.lower(), 0), reverse=True)


def run_sentinel(verdict: CouncilVerdict, scout_context: dict) -> CouncilVerdict:
    """Deduplicate cross-worker findings, then filter hallucinations by file path."""
    deduped = _dedup(verdict.findings)
    known_files = set(scout_context.get("changed_files", []))
    if known_files:
        deduped = [f for f in deduped if not f.file_path or f.file_path in known_files]
    return CouncilVerdict(
        findings=deduped,
        consensus_score=verdict.consensus_score,
        cost_usd=verdict.cost_usd,
        immunity_rules_applied=verdict.immunity_rules_applied,
    )
