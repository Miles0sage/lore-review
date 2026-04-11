from __future__ import annotations
from typing import Literal
from pydantic import BaseModel, Field


class ReviewRequest(BaseModel):
    repo_path: str
    pr_diff: str
    pr_id: str = "local"
    base_branch: str = "main"


class Finding(BaseModel):
    severity: Literal["critical", "high", "medium", "low", "info"]
    category: Literal["security", "performance", "style", "correctness", "agent_security", "static"]
    message: str
    file_path: str
    line_start: int = 0
    line_end: int = 0
    confidence: float = 1.0
    graph_evidence: list[str] = Field(default_factory=list)


class CouncilVerdict(BaseModel):
    findings: list[Finding]
    consensus_score: float = 0.0
    cost_usd: float = 0.0
    immunity_rules_applied: int = 0


class ReviewResult(BaseModel):
    pr_id: str
    verdict: CouncilVerdict
    darwin_rules_learned: int = 0
    total_cost_usd: float = 0.0


class ImmunityRule(BaseModel):
    rule_id: str
    pattern: str
    category: str
    confidence: float
    times_applied: int = 0
    created_at: str = ""
