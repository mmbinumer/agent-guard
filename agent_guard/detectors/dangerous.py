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
