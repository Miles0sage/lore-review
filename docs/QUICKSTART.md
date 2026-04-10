# Quickstart

## Install in your repo (30 seconds)

Add to `.github/workflows/lore-review.yml`:

```yaml
name: Lore Review
on: [pull_request]
jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: Miles0sage/lore-review@main
        with:
          github-token: ${{ secrets.GITHUB_TOKEN }}
```

That's it. lore-review will comment on every PR with findings, and get smarter with each review.

## CLI usage

```bash
pip install lore-review
git diff main...HEAD > pr.diff
lore-review --repo . --diff pr.diff
```
