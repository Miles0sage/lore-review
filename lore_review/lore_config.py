"""LoreConfig — reads/writes .lore.yml for explicit, reviewable suppression artifacts.

In strict mode, Darwin only applies suppressions from .lore.yml — not auto-learned ones.
Each suppression is an auditable artifact: rule_id + file_pattern + code_hash + reason.

Enterprise trust model:
  - Auto-learn: fast, but adversarial code could train away real vulns (unacceptable for CI gating)
  - .lore.yml: explicit, git-committed, PR-reviewable, content-addressed (hash-bound)
"""
from __future__ import annotations
import hashlib
import time
from pathlib import Path
from typing import Optional


LORE_YML = ".lore.yml"

# YAML written/read manually to avoid adding a dep (PyYAML not in base install)
# Format is intentionally simple — just key: value lines + list items with "- "


class LoreConfig:
    """Reads and writes .lore.yml suppression entries."""

    def __init__(self, repo_root: str | Path = "."):
        self._path = Path(repo_root) / LORE_YML
        self._data: dict = self._load()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_suppressions(self) -> list[dict]:
        """Return all explicit suppression entries from .lore.yml."""
        return list(self._data.get("suppressions", []))

    def add_suppression(
        self,
        rule_id: str,
        file_pattern: str,
        reason: str,
        code_snippet: str = "",
        approved_by: str = "cli",
        category: str = "security",
    ) -> dict:
        """Add a suppression entry to .lore.yml and persist."""
        code_hash = hashlib.sha256(code_snippet.encode()).hexdigest()[:12] if code_snippet else ""
        entry = {
            "rule_id": rule_id,
            "file_pattern": file_pattern,
            "code_hash": code_hash,
            "reason": reason,
            "category": category,
            "approved_by": approved_by,
            "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        if "suppressions" not in self._data:
            self._data["suppressions"] = []
        self._data["suppressions"].append(entry)
        self._save()
        return entry

    def is_suppressed(
        self,
        rule_id: str,
        file_path: str = "",
        code_snippet: str = "",
    ) -> bool:
        """Check if a finding is explicitly suppressed in .lore.yml.

        Matching logic (most-specific wins):
        1. rule_id match required
        2. file_pattern match: glob-style prefix, "*" matches all
        3. code_hash: if entry has a hash, snippet must match; "" = wildcard
        """
        code_hash = hashlib.sha256(code_snippet.encode()).hexdigest()[:12] if code_snippet else ""
        for entry in self.get_suppressions():
            if entry.get("rule_id") != rule_id:
                continue
            fp = entry.get("file_pattern", "*")
            if fp != "*" and not file_path.startswith(fp.rstrip("*")):
                continue
            entry_hash = entry.get("code_hash", "")
            if entry_hash and code_hash and entry_hash != code_hash:
                continue
            return True
        return False

    def has_any(self) -> bool:
        return bool(self._data.get("suppressions"))

    def path(self) -> Path:
        return self._path

    # ------------------------------------------------------------------
    # Serialisation (no PyYAML dep — hand-rolled for portability)
    # ------------------------------------------------------------------

    def _load(self) -> dict:
        if not self._path.exists():
            return {}
        text = self._path.read_text()
        return _parse_lore_yml(text)

    def _save(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(_dump_lore_yml(self._data))


# ------------------------------------------------------------------
# Minimal YAML-ish serialiser (handles our specific schema only)
# ------------------------------------------------------------------

def _parse_lore_yml(text: str) -> dict:
    """Parse .lore.yml — supports top-level keys and list-of-dicts under 'suppressions'."""
    data: dict = {}
    current_list: Optional[list] = None
    current_item: Optional[dict] = None
    in_suppressions = False

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if not line or line.startswith("#"):
            continue

        # Top-level key
        if not line.startswith(" ") and not line.startswith("-"):
            in_suppressions = False
            current_list = None
            current_item = None
            if ":" in line:
                key, _, val = line.partition(":")
                key = key.strip()
                val = val.strip()
                if key == "suppressions":
                    in_suppressions = True
                    data["suppressions"] = []
                    current_list = data["suppressions"]
                elif val:
                    data[key] = val
            continue

        if in_suppressions and current_list is not None:
            stripped = line.lstrip()
            if stripped.startswith("- "):
                # Start of new list item — inline key: val
                if current_item is not None:
                    current_list.append(current_item)
                k, _, v = stripped[2:].partition(":")
                current_item = {k.strip(): v.strip()}
            elif stripped.startswith("  ") or (line.startswith("  ") and ":" in stripped):
                # Continuation of current item
                if current_item is not None and ":" in stripped:
                    k, _, v = stripped.partition(":")
                    current_item[k.strip()] = v.strip()

    if current_item is not None and current_list is not None:
        current_list.append(current_item)

    return data


def _dump_lore_yml(data: dict) -> str:
    """Serialise to .lore.yml format."""
    lines = [
        "# .lore.yml — Explicit suppression rules for lore-review",
        "# Each entry is a reviewable artifact: rule_id + file + code_hash + reason",
        "# Commit this file. PR reviewers can audit every suppression decision.",
        "#",
        "# Fields:",
        "#   rule_id      — bug type key (e.g. eval_exec, pickle_load)",
        "#   file_pattern — path prefix or '*' for repo-wide (e.g. 'tests/')",
        "#   code_hash    — SHA-256[:12] of the suppressed code snippet ('' = wildcard)",
        "#   reason       — why this is a false positive",
        "#   approved_by  — who approved (github username, 'cli', etc.)",
        "#   category     — security | performance | correctness | style | agent_security",
        "#   created_at   — ISO-8601 timestamp",
        "",
    ]

    # Non-suppression top-level keys
    for k, v in data.items():
        if k != "suppressions":
            lines.append(f"{k}: {v}")

    suppressions = data.get("suppressions", [])
    if suppressions:
        lines.append("suppressions:")
        for entry in suppressions:
            first = True
            for field in ("rule_id", "file_pattern", "code_hash", "reason", "category", "approved_by", "created_at"):
                val = entry.get(field, "")
                if first:
                    lines.append(f"  - {field}: {val}")
                    first = False
                else:
                    lines.append(f"    {field}: {val}")
            lines.append("")

    return "\n".join(lines) + "\n"
