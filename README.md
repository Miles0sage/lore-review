The code reviewer that knows your codebase — and gets smarter every time it's wrong.

## Install

```bash
pip install lore-review
```

Or from source:

```bash
git clone https://github.com/your-org/lore-review
cd lore-review
pip install -e .
```

## Quickstart

```bash
# Review a PR diff from file
lore-review --repo /path/to/repo --diff changes.patch

# Review from stdin
git diff main...HEAD | lore-review --repo . --diff - --pr-id my-pr

# JSON output
lore-review --repo . --diff changes.patch --output json
```

## How Darwin Learning Works

Every time you run a review, Lore remembers:

```
PR Diff
   │
   ▼
Scout (maps changed files + graph context)
   │
   ▼
Council (4 specialist agents: Security / Perf / Correctness / Style)
   │
   ▼
Sentinel (filters hallucinations against graph facts)
   │
   ▼
Darwin Store (patterns that recur 2+ times → immunity rules)
   │
   ▼
ReviewResult (findings + rules learned + cost)
```

When a false positive recurs across reviews, Darwin compiles it into an **immunity rule** — the Council skips it next time. Over time, Lore stops crying wolf on your repo's known patterns.

Immunity rules are stored in `.lore-review/darwin.db` per repo. They're yours — portable, auditable, version-controllable.

## Pricing

| Plan | Price | What's included |
|------|-------|-----------------|
| Free | $0 | Unlimited local reviews, Darwin learning, CLI |
| Team | $49/mo | GitHub App, PR comments, team immunity rules, dashboard |
| Enterprise | $499/mo | Self-hosted, SSO, audit logs, SLA, custom Council roles |

## Roadmap

- [ ] GitHub App — auto-comment on PRs
- [ ] Code graph integration — deeper symbol-level analysis
- [ ] AI Factory Council — parallel specialist workers
- [ ] Darwin rule export/import across teams
- [ ] VS Code extension
- [ ] Slack/Teams alerts for critical findings
