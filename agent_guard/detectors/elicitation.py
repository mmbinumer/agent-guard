"""Detection of credential requests in elicitation.

`elicitation/create` lets a downstream server ask the client to put a
question to the *user*. That is the one MCP surface where a server can speak
to a human directly, which makes it the natural phishing channel: a
compromised server asks for an API key inside an otherwise ordinary-looking
setup flow.

The requested schema carries most of the signal. Asking for `environment` is
the normal use of elicitation; asking for `api_key` is alarming however
politely it is phrased, so field names are matched on word boundaries rather
than substrings - `monkey_name` contains "key" and asks for nothing.
"""
from __future__ import annotations

import re

# Matched against schema field names split into words.
_CREDENTIAL_WORDS = {
    "password", "passwd", "pwd", "passphrase",
    "secret", "token", "credential", "credentials",
    "apikey", "key",  # only as a whole word: "api_key" -> {"api", "key"}
    "privatekey", "seed", "mnemonic",
    "ssn", "sin", "cvv", "cvc", "pin",
    "card", "cardnumber", "iban",
    "otp", "mfa", "2fa",
}

# Field names whose words overlap the set above but are not credentials.
_ALLOWED = {"keyboard", "keyword", "monkey", "keynote", "cardinal"}

_MESSAGE_PATTERNS: list[re.Pattern] = [
    re.compile(
        r"\b(enter|provide|paste|confirm|supply|share|re-?enter)\b[^.?!]{0,40}\b"
        r"(password|api[\s_-]?key|secret|token|credential|passphrase|"
        r"seed[\s_-]?phrase|card\s*number|pin)\b",
        re.I,
    ),
    re.compile(r"\b(verify|confirm)\s+your\s+(identity|account)\b", re.I),
]

_WORD_SPLIT = re.compile(r"[^a-z0-9]+")


def _words(field: str) -> list[str]:
    """Split a field name into lowercase words across snake, kebab and camel
    case, so apiKey, API_KEY and api-key all reduce to the same thing."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", field)
    return [w for w in _WORD_SPLIT.split(spaced.lower()) if w]


def find_credential_requests(message: str, schema_fields: list[str]) -> list[str]:
    """Return descriptions of anything in this elicitation that asks the user
    for a secret. Empty means nothing suspicious was found, which is not proof
    the request is benign - see the README on tripwires."""
    matches: list[str] = []

    for field in schema_fields:
        words = _words(field)
        if any(w in _ALLOWED for w in words):
            continue
        joined = "".join(words)
        if joined in _CREDENTIAL_WORDS or any(w in _CREDENTIAL_WORDS for w in words):
            matches.append(f"schema field {field!r} requests a credential")

    for pattern in _MESSAGE_PATTERNS:
        found = pattern.search(message or "")
        if found:
            matches.append(f"message asks for a credential: {found.group(0)!r}")

    return matches
