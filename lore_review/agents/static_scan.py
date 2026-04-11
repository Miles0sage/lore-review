"""Static scanner — deterministic regex patterns for AI agent-specific vulnerabilities.

Runs BEFORE the Council (zero AI cost, ~0ms latency). Catches the patterns that
generic SAST tools (Bandit, Semgrep) miss because they lack agent-execution context.
"""
from __future__ import annotations

import re
from ..models import Finding

# ---------------------------------------------------------------------------
# Pattern registry: (regex, severity, message_template)
# Each pattern operates on individual diff HUNK lines (added lines only).
# ---------------------------------------------------------------------------

_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # --- Eval/exec chains -----------------------------------------------
    (
        re.compile(r'^\+\s*eval\s*\(\s*(?![\"\'])', re.MULTILINE),
        "critical",
        "eval() called with non-literal argument — arbitrary code execution if input is attacker-controlled",
    ),
    (
        re.compile(r'^\+\s*exec\s*\(\s*(?![\"\'])', re.MULTILINE),
        "critical",
        "exec() called with non-literal argument — arbitrary code execution if input is attacker-controlled",
    ),
    (
        re.compile(r'^\+.*\bcompile\s*\(.+,\s*[\'"]exec[\'"]\)', re.MULTILINE),
        "high",
        "compile(..., 'exec') with dynamic source — eval chain via compile+exec()",
    ),

    # --- Command injection via shell/os ----------------------------------
    (
        re.compile(r'^\+.*os\.system\s*\(\s*f[\'"]', re.MULTILINE),
        "critical",
        "os.system() with f-string argument — command injection if any variable is user-controlled",
    ),
    (
        re.compile(r'^\+.*os\.popen\s*\(\s*f[\'"]', re.MULTILINE),
        "critical",
        "os.popen() with f-string — command injection risk",
    ),
    (
        re.compile(r'^\+(?=.*subprocess\.[a-zA-Z]+\()(?=.*shell\s*=\s*True)(?=.*f[\'"]).*', re.MULTILINE),
        "critical",
        "subprocess with shell=True and f-string — classic command injection vector",
    ),
    (
        re.compile(r'^\+.*subprocess\.[a-zA-Z]+\(\s*f[\'"]', re.MULTILINE),
        "high",
        "subprocess called with f-string as command — verify no user-controlled variables",
    ),

    # --- Pipe-to-interpreter bypass -------------------------------------
    (
        re.compile(
            r'^\+.*[|&]\s*(?:bash|sh|zsh|python3?|python|node|ruby|perl|php|lua)\s*(?:-\s*|/dev/stdin\s*)?',
            re.MULTILINE | re.IGNORECASE,
        ),
        "critical",
        "Pipe-to-interpreter pattern — curl/wget piped to python3/bash/node executes remote code even if individual commands are allowlisted",
    ),

    # --- Tool poisoning / dynamic dispatch ------------------------------
    (
        re.compile(
            r'^\+.*getattr\s*\(\s*\w+\s*,\s*(?:user_input|request\.|payload\.|args\.|kwargs\.|tool_name|cmd|action)',
            re.MULTILINE,
        ),
        "critical",
        "getattr() with user-controlled name — tool poisoning: attacker can call any attribute on the object",
    ),
    (
        re.compile(
            r'^\+.*__import__\s*\(\s*(?![\"\'])',
            re.MULTILINE,
        ),
        "critical",
        "__import__() with dynamic module name — arbitrary module loading if input is attacker-controlled",
    ),
    (
        re.compile(
            r'^\+.*importlib\.import_module\s*\(\s*(?![\"\'])',
            re.MULTILINE,
        ),
        "high",
        "importlib.import_module() with dynamic name — verify module name cannot be attacker-controlled",
    ),

    # --- Prompt injection in code --------------------------------------
    (
        re.compile(
            r'^\+.*(?:messages|prompt|system_prompt)\s*[+]=?\s*.*(?:user_input|request\.|payload\.|args\.)',
            re.MULTILINE,
        ),
        "high",
        "User input concatenated directly into LLM prompt/messages — prompt injection: attacker can override system instructions",
    ),
    (
        re.compile(
            r'^\+.*f[\'"].*\{(?:user_input|user_message|query|prompt|instruction)\}.*[\'"].*(?:chat|complete|generate|invoke)',
            re.MULTILINE,
        ),
        "high",
        "User-controlled variable interpolated into LLM call — prompt injection risk",
    ),

    # --- Unbounded LLM cost loops ------------------------------------
    (
        re.compile(
            r'^\+\s*while\s+True\s*:',
            re.MULTILINE,
        ),
        "medium",
        "while True loop — verify LLM/agent calls inside have iteration limits and cost guards to prevent runaway API spend",
    ),

    # --- Insecure deserialization ------------------------------------
    (
        re.compile(r'^\+.*pickle\.loads?\s*\(', re.MULTILINE),
        "high",
        "pickle.load(s) called — deserialization RCE if input comes from untrusted source",
    ),
    (
        re.compile(r'^\+.*yaml\.load\s*\([^)]*\)', re.MULTILINE),
        "high",
        "yaml.load() without Loader=yaml.SafeLoader — can deserialize arbitrary Python objects",
    ),

    # --- Homograph URLs -----------------------------------------------
    (
        re.compile(
            r'^\+.*https?://[^\s\'\"]*[\u0430-\u044f\u0410-\u042f\u0451\u0401\u0370-\u03FF\u0400-\u04FF][^\s\'\"]*',
            re.MULTILINE | re.UNICODE,
        ),
        "high",
        "IDN homograph URL — Cyrillic/Greek lookalike characters in URL can redirect to attacker-controlled domain",
    ),

    # --- ANSI/OSC terminal injection ----------------------------------
    (
        re.compile(
            r'^\+.*(?:print|log|output|stdout)\s*\(.*\\x1b|\\033|\\x9b',
            re.MULTILINE,
        ),
        "medium",
        "ANSI/OSC escape sequence in output — can hijack terminal, override display, or exfiltrate data via OSC sequences",
    ),

    # --- Hardcoded credentials ---------------------------------------
    (
        re.compile(
            r'^\+\s*(?:api_key|secret|password|token|AUTH_TOKEN|API_KEY)\s*=\s*[\'"][^\'"]{8,}[\'"]',
            re.MULTILINE | re.IGNORECASE,
        ),
        "critical",
        "Hardcoded credential in source — rotate immediately; use environment variables or a secret manager",
    ),

    # --- Path traversal ----------------------------------------------
    (
        re.compile(
            r'^\+.*open\s*\(\s*(?:user_input|request\.|payload\.|args\.|f[\'"].*\{)',
            re.MULTILINE,
        ),
        "high",
        "open() with potentially user-controlled path — path traversal: attacker can read/write arbitrary files",
    ),
]


def _extract_file_path(hunk_header: str) -> str:
    """Extract file path from diff hunk header like '+++ b/path/to/file.py'."""
    m = re.search(r'\+\+\+\s+(?:b/)?(\S+)', hunk_header)
    return m.group(1) if m else ""


def _extract_line_number(lines: list[str], match_start: int) -> int:
    """Estimate line number from diff position."""
    # Count @@ -x,y +start,len @@ markers
    text_before = "".join(lines)[:match_start]
    hunk_headers = re.findall(r'@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@', text_before)
    if not hunk_headers:
        return 0
    base_line = int(hunk_headers[-1])
    # Count added/context lines since last @@ header
    last_hunk_pos = text_before.rfind("@@")
    after_hunk = text_before[last_hunk_pos:]
    added_lines = sum(1 for l in after_hunk.splitlines() if l.startswith("+") and not l.startswith("+++"))
    return base_line + added_lines


def run_static_scan(diff: str) -> list[Finding]:
    """Scan diff for deterministic agent-security patterns. Returns findings for added lines only."""
    findings: list[Finding] = []
    seen: set[str] = set()

    # Split by file sections
    current_file = ""
    for segment in re.split(r'(?=^diff --git)', diff, flags=re.MULTILINE):
        # Extract file path from diff header
        file_match = re.search(r'\+\+\+\s+(?:b/)?(\S+)', segment)
        if file_match:
            current_file = file_match.group(1)

        # Skip binary files and deleted files
        if "Binary files" in segment or not current_file.endswith(
            (".py", ".js", ".ts", ".rb", ".php", ".go", ".sh", ".bash")
        ):
            continue

        for pattern, severity, message in _PATTERNS:
            for m in pattern.finditer(segment):
                line_text = m.group(0)[:120]
                # Dedup: same file + pattern + first 60 chars of match
                key = f"{current_file}:{pattern.pattern[:40]}:{line_text[:60]}"
                if key in seen:
                    continue
                seen.add(key)

                # Estimate line number
                line_no = _extract_line_number(segment.splitlines(keepends=True), m.start())

                findings.append(Finding(
                    severity=severity,
                    category="security",
                    message=message,
                    file_path=current_file,
                    line_start=line_no,
                    confidence=0.9,
                ))

    return findings
