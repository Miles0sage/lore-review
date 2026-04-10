"""Reads code-review-graph MCP if available, falls back to diff-only mode."""
import httpx
from pathlib import Path


class GraphReader:
    def __init__(self, mcp_url: str = "http://localhost:8000"):
        self.mcp_url = mcp_url
        self._available = None

    def is_available(self) -> bool:
        if self._available is None:
            try:
                httpx.get(f"{self.mcp_url}/health", timeout=2.0)
                self._available = True
            except Exception:
                self._available = False
        return self._available

    def get_pr_context(self, diff: str, repo_path: str) -> dict:
        if not self.is_available():
            return {"graph_available": False, "changed_files": self._parse_diff_files(diff), "symbols": [], "risk_score": 0.5}
        try:
            resp = httpx.post(f"{self.mcp_url}/tools/get_review_context_tool",
                            json={"diff": diff, "repo_path": repo_path}, timeout=30.0)
            data = resp.json()
            data["graph_available"] = True
            return data
        except Exception:
            return {"graph_available": False, "changed_files": self._parse_diff_files(diff), "symbols": [], "risk_score": 0.5}

    def _parse_diff_files(self, diff: str) -> list[str]:
        files = []
        for line in diff.splitlines():
            if line.startswith("+++ b/"):
                files.append(line[6:])
        return files
