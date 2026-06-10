from __future__ import annotations

import base64
import binascii
import re

# Known secret patterns: (name, regex)
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("openai_key", re.compile(r"sk-[A-Za-z0-9]{20,}")),
    ("github_token", re.compile(r"ghp_[A-Za-z0-9]{30,}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("private_key_block", re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
    )),
]

# Generic high-entropy token: long run of mixed alnum, no spaces
_GENERIC_TOKEN = re.compile(r"\b[A-Za-z0-9+/_=-]{24,}\b")
_MIN_ENTROPY = 3.5


def _shannon_entropy(s: str) -> float:
    import math
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _scan_raw(text: str) -> set[str]:
    found: set[str] = set()

    for _name, pattern in SECRET_PATTERNS:
        for m in pattern.finditer(text):
            found.add(m.group(0))

    for m in _GENERIC_TOKEN.finditer(text):
        candidate = m.group(0)
        if _shannon_entropy(candidate) >= _MIN_ENTROPY:
            found.add(candidate)

    return found


def _decode_variants(text: str) -> list[str]:
    """One level of base64/hex decoding of substrings, best-effort."""
    variants: list[str] = []

    for m in re.finditer(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        token = m.group(0)
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="strict")
            variants.append(decoded)
        except (binascii.Error, ValueError, UnicodeDecodeError):
            pass

    for m in re.finditer(r"[0-9a-fA-F]{32,}", text):
        token = m.group(0)
        if len(token) % 2 == 0:
            try:
                decoded = bytes.fromhex(token).decode("utf-8", errors="strict")
                variants.append(decoded)
            except (ValueError, UnicodeDecodeError):
                pass

    return variants


def find_secrets(text: str) -> list[str]:
    """Return distinct secret-like strings found in raw text and one-level
    base64/hex-decoded variants of substrings within it."""
    found = _scan_raw(text)

    for variant in _decode_variants(text):
        found |= _scan_raw(variant)

    return sorted(found)
