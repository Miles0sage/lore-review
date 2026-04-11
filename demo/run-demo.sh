#!/bin/bash
set -euo pipefail

# Resolve demo directory relative to this script
DEMO_DIR="$(cd "$(dirname "$0")" && pwd)"
DIFF_FILE="$DEMO_DIR/vulnerable-agent.diff"

if [ ! -f "$DIFF_FILE" ]; then
    echo "Error: vulnerable-agent.diff not found at $DIFF_FILE" >&2
    exit 1
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              lore-review Interactive Demo                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Scanning a simulated AI agent PR for security vulnerabilities..."
echo "This diff adds tool execution, code sandboxing, and an agent loop"
echo "to a fictional agent framework — with 6 intentional flaws."
echo ""

lore-review scan "$DIFF_FILE" --mode security --fail-on never

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Try other output formats:"
echo ""
echo "  SARIF (GitHub Code Scanning):  lore-review scan $DIFF_FILE --output sarif"
echo "  JSON (programmatic):           lore-review scan $DIFF_FILE --output json"
echo "  Fix suggestions:               lore-review scan $DIFF_FILE --scaffold"
echo ""
echo "Try on your own repo:"
echo ""
echo "  git diff HEAD~5 | lore-review scan - --mode security"
echo "  git diff main...HEAD | lore-review scan -"
echo "  lore-review pr https://github.com/owner/repo/pull/123"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
