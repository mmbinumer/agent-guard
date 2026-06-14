from __future__ import annotations

import re

# (name, regex) - regex applied case-insensitively
_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("rm_rf", re.compile(r"rm\s+(-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*)\s", re.I)),
    ("curl_pipe_shell", re.compile(r"(curl|wget)\b[^\n|]*\|\s*(sh|bash|zsh|python)\b", re.I)),
    ("chmod_777", re.compile(r"chmod\s+(-[a-zA-Z]+\s+)?0?777\b", re.I)),
    (
        "sql_delete_no_where",
        re.compile(r"\bDELETE\s+FROM\s+[^\s;]+(?!.*\bWHERE\b)(?:\s*;|\s*$)", re.I),
    ),
    (
        "sql_drop_table",
        re.compile(r"\bDROP\s+TABLE\b", re.I),
    ),
    (
        "sql_update_no_where",
        re.compile(r"\bUPDATE\s+[^\s]+\s+SET\b(?!.*\bWHERE\b)(?:\s*;|\s*$)", re.I),
    ),
]


def find_dangerous_commands(text: str) -> list[str]:
    """Return the matched substrings for any dangerous command pattern found."""
    matches: list[str] = []
    for _name, pattern in _PATTERNS:
        for m in pattern.finditer(text):
            matches.append(m.group(0).strip())
    return matches


# Heuristic tripwires for malicious *inbound* args - lower precision than the
# command patterns above, so the pipeline defaults these to "warn", not "block".
# Each entry is (rule_name, regex). Scan individual string arg values, not the
# JSON blob, to avoid escaping artifacts and cross-arg false matches.

# Path traversal: deliberately conservative. A bare "../" is legitimate in most
# codebases, so we only flag high-signal cases (encoded escapes, null bytes,
# deep climbs, and well-known sensitive targets).
_PATH_TRAVERSAL_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("encoded_traversal", re.compile(r"%2e%2e|\.\.%2f|\.\.%5c|%252e", re.I)),
    ("null_byte", re.compile(r"%00|\x00")),
    ("multi_level_traversal", re.compile(r"(?:\.\./){3,}|(?:\.\.\\){3,}")),
    (
        "sensitive_path",
        re.compile(r"/etc/(?:passwd|shadow)\b|[\\/]\.ssh[\\/]|system32[\\/]config", re.I),
    ),
]

# SQL injection: classic signatures. Destructive DROP/DELETE/UPDATE are already
# covered by the command patterns above, so these target injection structure
# (tautologies, stacked queries, UNION-based, comment terminators).
_SQL_INJECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("sql_tautology", re.compile(r"'\s*or\s*'?1'?\s*=\s*'?1|\bor\s+1\s*=\s*1\b", re.I)),
    ("sql_stacked_query", re.compile(r"'\s*;\s*(?:drop|delete|insert|update)\b", re.I)),
    ("sql_union_select", re.compile(r"\bunion\s+(?:all\s+)?select\b", re.I)),
    ("sql_comment_injection", re.compile(r"'\s*(?:--|#)")),
]


def _find_named(text: str, patterns: list[tuple[str, re.Pattern]]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for name, pattern in patterns:
        for m in pattern.finditer(text):
            out.append((name, m.group(0).strip()))
    return out


def find_path_traversal(text: str) -> list[tuple[str, str]]:
    """Return (rule_name, matched_substring) for path-traversal signatures."""
    return _find_named(text, _PATH_TRAVERSAL_PATTERNS)


def find_sql_injection(text: str) -> list[tuple[str, str]]:
    """Return (rule_name, matched_substring) for SQL-injection signatures."""
    return _find_named(text, _SQL_INJECTION_PATTERNS)
