from __future__ import annotations

import re

# Verbatim/near-verbatim injection phrasing only - this is a tripwire for
# unsophisticated injection attempts, not a defense against rephrased or
# obfuscated injections. See README "Limitations".
_PATTERNS: list[re.Pattern] = [
    re.compile(r"ignore (all )?(previous|prior|above) instructions", re.I),
    re.compile(r"disregard (all )?(previous|prior|above)( instructions| system prompt)?", re.I),
    re.compile(r"you are now\b", re.I),
    re.compile(r"new instructions?:", re.I),
    re.compile(r"system prompt", re.I),
    re.compile(r"developer mode", re.I),
]


def find_injection_markers(text: str) -> list[str]:
    matches: list[str] = []
    for pattern in _PATTERNS:
        for m in pattern.finditer(text):
            matches.append(m.group(0))
    return matches
