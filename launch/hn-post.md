# Show HN: We scanned AutoGPT and CrewAI -- here's what we found

We built lore-review to catch security issues that generic SAST tools miss in AI agent codebases. To validate it, we pointed it at three popular open-source agent frameworks. The results were uncomfortable.

**What we found:**

- **AutoGPT** removed Pydantic's `extra="forbid"` from agent input models. This means an attacker can inject arbitrary fields into agent configurations -- a direct path to prompt injection in agentic workflows where config flows into LLM context.

- **AutoGPT** uses `eval()` in its benchmark harness (`agbenchmark/`). If benchmark inputs are ever sourced from untrusted data (community challenges, external test suites), this is arbitrary code execution.

- **CrewAI** calls `pickle.load()` on task outputs with an explicit `# noqa: S301` suppressing Bandit's deserialization warning. Pickle deserialization of untrusted data is a well-known RCE vector -- the suppression comment means someone saw the warning and chose to ignore it.

**Why generic tools miss these:**

Semgrep, Bandit, and CodeQL are designed for traditional applications. They don't model agentic data flow -- the path from user input to LLM prompt to tool execution to output. A `pickle.load()` in a web app is suspicious. A `pickle.load()` on data that an LLM agent decided to serialize is a different threat class entirely. Similarly, removing input validation on a Pydantic model is a low-severity finding in a REST API, but in an agent framework where those inputs become part of the prompt, it's a prompt injection surface.

**Benchmark (8 agentic vulnerability patterns, 10 test cases):**

| Tool | Detection Rate | Agentic Context | Cost/PR |
|------|---------------|-----------------|---------|
| lore-review | 8/10 | Yes | $0.004 |
| Semgrep | 3/10 | No | Free |
| Bandit | 2/10 | No | Free |
| CodeQL | 3/10 | No | Free |

lore-review catches more because it understands what "untrusted" means in an agent context: LLM outputs, tool results, and user prompts all flow through the same pipeline, and any of them can be attacker-controlled.

**How it works:**

AST-level analysis combined with an LLM reviewer that understands agentic patterns. Darwin learning means it gets better from every codebase it reviews -- findings from one scan improve detection for the next. Enterprise teams can lock down rules via `.lore.yml`.

```
pip install lore-review
lore-review scan .
```

GitHub: https://github.com/Miles0sage/lore-review

We've submitted responsible disclosure to both AutoGPT and CrewAI maintainers with a 90-day timeline. Happy to answer questions about the methodology or findings.
