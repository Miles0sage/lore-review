import sqlite3
import hashlib
import json
import time
from pathlib import Path
from .models import ImmunityRule, Finding


class DarwinStore:
    def __init__(self, db_path: Path = Path(".lore-review/darwin.db")):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._db = str(db_path)
        self._init_schema()

    def _init_schema(self):
        with sqlite3.connect(self._db) as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS immunity_rules (
                rule_id TEXT PRIMARY KEY, pattern TEXT, category TEXT,
                confidence REAL, times_applied INTEGER DEFAULT 0,
                created_at TEXT)""")
            conn.execute("""CREATE TABLE IF NOT EXISTS review_misses (
                id INTEGER PRIMARY KEY AUTOINCREMENT, repo_id TEXT,
                pattern TEXT, category TEXT, was_caught INTEGER,
                recorded_at REAL)""")

    def repo_id_from_path(self, repo_path: str) -> str:
        return hashlib.sha256(repo_path.encode()).hexdigest()[:16]

    def get_rules(self, repo_id: str) -> list[ImmunityRule]:
        with sqlite3.connect(self._db) as conn:
            rows = conn.execute(
                "SELECT rule_id, pattern, category, confidence, times_applied, created_at FROM immunity_rules WHERE rule_id LIKE ?",
                (f"{repo_id}%",)
            ).fetchall()
        return [ImmunityRule(rule_id=r[0], pattern=r[1], category=r[2],
                             confidence=r[3], times_applied=r[4], created_at=r[5]) for r in rows]

    def record_miss(self, repo_id: str, finding: Finding, was_caught: bool):
        with sqlite3.connect(self._db) as conn:
            conn.execute(
                "INSERT INTO review_misses (repo_id, pattern, category, was_caught, recorded_at) VALUES (?,?,?,?,?)",
                (repo_id, finding.message[:100], finding.category, int(was_caught), time.time())
            )

    def compile_rules(self, repo_id: str) -> list[ImmunityRule]:
        """Cluster misses into immunity rules."""
        with sqlite3.connect(self._db) as conn:
            rows = conn.execute(
                "SELECT pattern, category, COUNT(*) as cnt FROM review_misses WHERE repo_id=? GROUP BY pattern, category HAVING cnt >= 2",
                (repo_id,)
            ).fetchall()
        rules = []
        for pattern, category, cnt in rows:
            rule_id = f"{repo_id}_{hashlib.sha256(pattern.encode()).hexdigest()[:8]}"
            rule = ImmunityRule(rule_id=rule_id, pattern=pattern, category=category,
                               confidence=min(0.5 + cnt * 0.1, 0.95),
                               times_applied=cnt, created_at=time.strftime("%Y-%m-%dT%H:%M:%SZ"))
            with sqlite3.connect(self._db) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO immunity_rules VALUES (?,?,?,?,?,?)",
                    (rule.rule_id, rule.pattern, rule.category, rule.confidence, rule.times_applied, rule.created_at)
                )
            rules.append(rule)
        return rules
