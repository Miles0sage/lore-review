# lore-review Demo

Self-contained demo that shows lore-review finding real vulnerabilities in an AI agent codebase.

## Quick Start

```bash
pip install lore-review
cd demo/
bash run-demo.sh
```

## What It Scans

`vulnerable-agent.diff` is a realistic PR that adds tool execution, code sandboxing, and an autonomous agent loop to a fictional framework. It contains 6 intentional security flaws that lore-review's static scanner and council workers catch:

| # | Vulnerability | Severity | File |
|---|---------------|----------|------|
| 1 | `eval()` on LLM-generated code | Critical | `agent/sandbox.py` |
| 2 | `subprocess.run(shell=True)` with f-string interpolation | Critical | `agent/tool_executor.py` |
| 3 | `getattr()` with user-controlled tool name (tool poisoning) | Critical | `agent/tool_executor.py` |
| 4 | `pickle.load()` without HMAC verification | High | `agent/sandbox.py` |
| 5 | User input concatenated into LLM prompt (prompt injection) | High | `agent/orchestrator.py` |
| 6 | `while True` loop with no `max_iterations` guard | Medium | `agent/orchestrator.py` |

## Output Formats

```bash
# Human-readable (default)
lore-review scan vulnerable-agent.diff --mode security

# SARIF for GitHub Code Scanning
lore-review scan vulnerable-agent.diff --output sarif

# JSON for programmatic consumption
lore-review scan vulnerable-agent.diff --output json

# With fix suggestions
lore-review scan vulnerable-agent.diff --scaffold
```

## Try On Your Own Code

```bash
# Review recent changes
git diff HEAD~5 | lore-review scan - --mode security

# Review a feature branch
git diff main...HEAD | lore-review scan -

# Review a GitHub PR directly
lore-review pr https://github.com/owner/repo/pull/123

# CI gate: fail if any critical finding
git diff main...HEAD | lore-review scan - --fail-on critical
```
