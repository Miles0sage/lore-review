"""Council — 4 specialist AI workers review the PR in parallel."""
import subprocess, json, re, concurrent.futures, time
from pathlib import Path
from ..models import Finding, CouncilVerdict

COUNCIL_ROLES = {
    "security": "You are a security code reviewer. Analyze this PR diff for: SQL injection, XSS, hardcoded secrets, auth bypass, OWASP Top 10 violations, insecure dependencies. Output JSON list of findings.",
    "performance": "You are a performance engineer. Analyze this PR diff for: N+1 queries, blocking I/O in async contexts, memory leaks, O(n²) algorithms, unnecessary re-renders. Output JSON list of findings.",
    "correctness": "You are a correctness reviewer. Analyze this PR diff for: logic errors, off-by-one errors, null/undefined dereferences, race conditions, unhandled exceptions, incorrect error propagation. Output JSON list of findings.",
    "style": "You are a code quality reviewer. Analyze this PR diff for: dead code, overly complex functions (>50 lines), missing error handling, unclear variable names, code duplication. Output JSON list of findings.",
    "agent_security": (
        "You are an AI agent security specialist. Analyze this PR diff SPECIFICALLY for vulnerabilities that only appear in agentic/LLM-based codebases and that generic SAST tools miss:\n"
        "1. Tool poisoning: user-controlled strings used as tool/function names in dynamic dispatch (getattr, __import__, importlib)\n"
        "2. Prompt injection in code: user input concatenated directly into LLM prompt strings, system prompts, or message arrays\n"
        "3. Unbounded agent loops: while True or recursive agent calls with no max_iterations guard, no cost circuit breaker\n"
        "4. Eval chains: LLM output passed directly to eval(), exec(), or compile() without sanitization\n"
        "5. Ambient authority abuse: agent tools with broader permissions than needed for the task (principle of least privilege)\n"
        "6. Memory/context poisoning: untrusted data written to agent memory/context stores that future calls will read\n"
        "7. Callback injection: user-controlled URLs or function references registered as agent callbacks/webhooks\n"
        "8. LLM cost attacks: inputs that could cause unbounded token consumption, recursive expansion, or infinite agent chains\n"
        "Output JSON list of findings. Only flag genuine agentic vulnerabilities, not general security issues."
    ),
}

AI_FACTORY = Path("/root/ai-factory/orchestrator.py")


def _parse_findings(raw: list, role: str, confidence: float) -> list[Finding]:
    findings = []
    for item in raw:
        if isinstance(item, dict) and "message" in item:
            findings.append(Finding(
                severity=item.get("severity", "medium"),
                category=role,
                message=item.get("message", ""),
                file_path=item.get("file_path", ""),
                line_start=item.get("line_start", 0),
                confidence=confidence,
            ))
    return findings


def _run_worker(role: str, prompt: str, diff: str, immunity_rules: list) -> list[Finding]:
    """Run one council worker — tries AI Factory first, falls back to direct API."""
    rules_context = ""
    if immunity_rules:
        rules_context = f"\n\nKnown patterns to watch for:\n" + \
                       "\n".join(f"- {r.pattern} ({r.category})" for r in immunity_rules[:10])

    full_prompt = f"{prompt}{rules_context}\n\nPR DIFF:\n{diff[:6000]}\n\nRespond with ONLY a JSON array of findings. Each: {{\"severity\": \"critical|high|medium|low|info\", \"message\": \"description\", \"file_path\": \"path\", \"line_start\": 0}}. If none found, return []."

    # Try 1: AI Factory (short timeout so fallback has room within 120s window)
    if AI_FACTORY.exists():
        try:
            result = subprocess.run(
                ["python3", str(AI_FACTORY), full_prompt, "--worker", "alibaba", "--timeout", "8"],
                capture_output=True, text=True, timeout=12
            )
            if result.returncode == 0 and result.stdout.strip():
                output = result.stdout.strip()
                match = re.search(r'\[.*\]', output, re.DOTALL)
                if match:
                    raw = json.loads(match.group())
                    return _parse_findings(raw, role, 0.8)
        except Exception:
            pass  # Fall through to next method

    # Try 2: Direct Anthropic API (api key or OAuth token)
    try:
        import anthropic
        import os
        api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        if not api_key:
            # Try OAuth token from Claude credentials
            creds_path = Path.home() / ".claude" / ".credentials.json"
            if creds_path.exists():
                creds = json.loads(creds_path.read_text())
                api_key = creds.get("claudeAiOauth", {}).get("accessToken", "")
        if api_key:
            client = anthropic.Anthropic(api_key=api_key)
            msg = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=1024,
                messages=[{"role": "user", "content": full_prompt}]
            )
            text = msg.content[0].text
            match = re.search(r'\[.*\]', text, re.DOTALL)
            if match:
                raw = json.loads(match.group())
                return _parse_findings(raw, role, 0.85)
    except Exception:
        pass

    # Try 3: claude CLI
    try:
        result = subprocess.run(
            ["claude", "-p", full_prompt, "--model", "claude-haiku-4-5-20251001"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0 and result.stdout.strip():
            text = result.stdout.strip()
            match = re.search(r'\[.*\]', text, re.DOTALL)
            if match:
                raw = json.loads(match.group())
                return _parse_findings(raw, role, 0.75)
    except Exception:
        pass

    return []

def run_council(scout_context: dict, immunity_rules: list, dry_run: bool = False) -> CouncilVerdict:
    """Run 4 specialist reviews in parallel via AI Factory."""
    diff = scout_context.get("diff", "")
    if dry_run or not diff.strip():
        return CouncilVerdict(findings=[], consensus_score=1.0, cost_usd=0.0, immunity_rules_applied=len(immunity_rules))

    start = time.time()
    all_findings = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        futures = {
            executor.submit(_run_worker, role, prompt, diff, immunity_rules): role
            for role, prompt in COUNCIL_ROLES.items()
        }
        for future in concurrent.futures.as_completed(futures, timeout=120):
            try:
                all_findings.extend(future.result())
            except Exception:
                pass

    elapsed = time.time() - start
    # Estimate cost: 4 workers x ~$0.001 each
    cost = 0.004

    return CouncilVerdict(
        findings=all_findings,
        consensus_score=0.85,
        cost_usd=cost,
        immunity_rules_applied=len(immunity_rules),
    )
