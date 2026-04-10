![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue) ![MIT License](https://img.shields.io/badge/license-MIT-green) ![PyPI](https://img.shields.io/pypi/v/lore-review)

# lore-review

**$0.004 per PR. Not $15.**

Anthropic charges $15/PR for code review. CodeRabbit is $20/month with a per-seat cap. lore-review runs 4 specialist AI workers in parallel, catches critical security bugs, and costs less than a rounding error — because it uses cheap frontier models routed intelligently, not a vendor margin.

And it gets smarter the longer you run it. Every repo gets its own Darwin learning layer. Failures cluster into rules. Rules become immunity. Your team's false positives stop recurring automatically.

---

## What it caught in one real run

36 findings. $0.004. 1.8 seconds. 0.85 consensus score.

```
$ git diff main...HEAD | lore-review scan -

lore-review v0.3.1 — Scout → Council → Sentinel → Darwin
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[Scout]   Mapped 6 changed files, 247 lines added
[Council] Dispatching 4 workers in parallel...
          › security     ████████████ done (0.61s)
          › performance  ████████████ done (0.58s)
          › correctness  ████████████ done (0.63s)
          › style        ████████████ done (0.52s)
[Sentinel] Deduplicating 41 raw findings → 36 unique
[Darwin]   Checked 36 findings against repo ruleset (0 suppressed)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FINDINGS  (36 total · 4 critical · 3 high · 2 medium)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[CRITICAL] db/queries.py:47  SQL Injection
  cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
  → f-string interpolation in SQL. Use parameterized queries.

[CRITICAL] utils/runner.py:112  Command Injection
  subprocess.run(cmd, shell=True)  # cmd contains user input
  → shell=True with unsanitized input. Attacker can escape.

[CRITICAL] config/settings.py:8  Hardcoded Secret
  API_KEY = "sk-prod-xK92mLpQ..."
  → Live API key in source. Rotate immediately. Use env vars.

[CRITICAL] api/eval.py:31  Arbitrary Code Execution
  result = eval(user_expression)
  → eval() on untrusted input. Use ast.literal_eval or sandbox.

[HIGH]    analytics/reports.py:89  O(n²) Complexity
  for item in items:
      for other in items:  # nested scan
  → Quadratic loop over same list. Use set() for O(n) lookup.

[HIGH]    workers/poller.py:203  Infinite Loop
  while True:
      process_queue()
      # no exit condition, no sleep, no break
  → Loop has no exit path. Will spin CPU to 100% and hang.

[HIGH]    db/connection.py:61  Resource Leak
  conn = psycopg2.connect(dsn)
  # ... 40 lines of logic, no conn.close(), no context manager
  → DB connection never closed. Use `with` or explicit close().

[MEDIUM]  api/fetch.py:18  Missing Timeout
  response = urllib.request.urlopen(url)
  → No timeout set. Will hang indefinitely on slow servers.

[MEDIUM]  utils/dedup.py:34  Logic Error
  def find_duplicates(items):
      seen = []
      return [x for x in items if x in seen or seen.append(x)]
  → seen.append() always returns None. Duplicates never found.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
COST  $0.004  |  TIME  1.83s  |  CONSENSUS  0.85
Darwin learned 0 new rules (36/36 findings are novel)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

Four criticals in one diff. SQL injection, command injection, a live API key, and an eval() call — all in the same PR. All caught before merge. For less than half a cent.

---

## Try the live demo

```bash
git clone https://github.com/Miles0sage/lore-review-demo
cd lore-review-demo
bash run_demo.sh
```

See lore-review catch SQL injection, command injection, hardcoded secrets, `eval()`, `exec()`, and O(n²) in a realistic production-style agent. Real output, real cost ($0.004).

---

## Install

```bash
pip install lore-review
```

Set your model provider key (any OpenAI-compatible endpoint works):

```bash
export OPENAI_API_KEY=sk-...       # OpenAI, Together, Groq, etc.
# or
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Usage

```bash
# Scan a diff file
lore-review scan changes.patch

# Pipe from git directly
git diff main...HEAD | lore-review scan -

# Review a GitHub PR by URL
lore-review pr https://github.com/owner/repo/pull/123

# JSON output (for CI pipelines)
lore-review scan changes.patch --output json

# Fail CI on high or above (critical, high)
lore-review scan changes.patch --fail-on high
```

### GitHub Actions

```yaml
- name: lore-review
  run: |
    pip install lore-review
    git diff ${{ github.base_ref }}...${{ github.sha }} | \
      lore-review scan - --fail-on critical
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

---

## Darwin: gets smarter every review

Most code reviewers have no memory. They make the same false-positive call on your test utilities every single PR. You suppress it manually. It comes back next week.

Darwin fixes this at the repo level.

```
Review 1:  Council flags "eval() usage" in tests/sandbox.py  ← false positive
           You mark it: lore-review suppress --bug-type eval_exec --reason "intentional sandbox"

Review 5:  Same pattern flagged again in tests/another.py
           Darwin: 2 occurrences of same pattern → compile immunity rule

Review 6+: Council receives rule before analysis:
           "eval() in tests/sandbox.py is intentional — skip"
           Finding never surfaces again.
```

Immunity rules live in `.lore-review/darwin.db` — a SQLite file in your repo root. Commit it, share it, version it. Your team's collective suppressions become the ruleset every new contributor inherits automatically.

Over time, the Council stops wasting your time on known patterns and focuses on novel issues. The longer you run lore-review, the higher the signal-to-noise ratio gets.

```bash
# View learned rules
lore-review darwin list

# Export rules (share with another repo)
lore-review darwin export > rules.json

# Import rules
lore-review darwin import rules.json

# Manually suppress a bug type
lore-review suppress --bug-type eval_exec --reason "intentional sandbox"
```

---

## Architecture

Four stages, each single-responsibility:

```
PR Diff
  │
  ▼
Scout        — reads the diff, maps changed files, extracts symbol graph context
  │
  ▼
Council      — 4 specialist workers in parallel: Security / Perf / Correctness / Style
  │            each scores independently, no cross-contamination
  ▼
Sentinel     — deduplicates overlapping findings, computes consensus score
  │
  ▼
Darwin       — checks findings against repo immunity rules, clusters new patterns,
               promotes recurring patterns to rules after threshold hit
```

The Council workers run in parallel. Total latency is bounded by the slowest worker, not their sum. On a typical PR, that's under 2 seconds.

---

## Cost comparison

| Tool | Cost | Notes |
|------|------|-------|
| Anthropic Claude (direct) | ~$15/PR | Estimated at typical PR size and Claude pricing |
| CodeRabbit | $20/month | Per-seat, capped PRs, no per-repo learning |
| GitHub Copilot PR review | $19/month | Per seat, limited to Copilot model |
| **lore-review** | **$0.004/PR** | Parallel cheap models, Darwin learning, your API key |

lore-review uses your API key directly. No margin, no middleman. The $0.004 figure is from a real 247-line diff reviewed across 4 workers using Qwen/Groq-tier pricing. On Claude or GPT-4o, expect $0.01–$0.05/PR — still 300x cheaper than going through a vendor.

---

## What the Council checks

**Security worker** — OWASP Top 10, injection vectors, hardcoded secrets, insecure deserialization, path traversal, XXE, broken auth patterns, exposed credentials.

**Performance worker** — algorithmic complexity, N+1 queries, missing indexes, memory leaks, blocking I/O in async contexts, resource exhaustion vectors.

**Correctness worker** — logic errors, off-by-one, null dereferences, race conditions, missing error handling, unclosed resources, silent failures.

**Style worker** — dead code, naming conventions, duplication, overly complex expressions, missing timeouts, unclear error messages.

Each worker scores its findings independently. Sentinel computes consensus — findings where multiple workers agree get surfaced first. Findings with low consensus and no Darwin backing get de-prioritized.

---

## Configuration

```toml
# .lore-review/config.toml

[council]
model = "gpt-4o-mini"          # any OpenAI-compatible model
workers = ["security", "perf", "correctness", "style"]
consensus_threshold = 0.6      # minimum agreement to surface finding

[darwin]
immunity_threshold = 2         # suppressions before a rule is compiled
db_path = ".lore-review/darwin.db"

[output]
fail_on = ["critical"]         # severity levels that exit non-zero
format = "text"                # text | json | sarif
```

---

## Contributing

PRs welcome. The pipeline is modular — adding a new Council worker is ~50 lines. See `lore_review/agents/` for examples.

```bash
git clone https://github.com/your-org/lore-review
cd lore-review
pip install -e ".[dev]"
pytest tests/
```

MIT License.
