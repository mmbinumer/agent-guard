from __future__ import annotations

import base64
import binascii
import fnmatch
import re
from collections import OrderedDict


def _decode_variants(text: str) -> list[str]:
    """Same one-level base64/hex decoding as the secret scanner, used so
    taint matching catches simple encoded leaks too."""
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


class TaintStore:
    """Session-scoped store of values read from sensitive sources, used to
    detect when those values later appear in calls to external sinks.

    Entries are stored as an ordered dict of value -> source, FIFO-evicted
    once max_entries is exceeded. `truncated` becomes True the first time
    eviction occurs (logged once by the pipeline)."""

    def __init__(self, max_value_bytes: int, max_entries: int):
        self.max_value_bytes = max_value_bytes
        self.max_entries = max_entries
        self._entries: OrderedDict[str, str] = OrderedDict()
        self.truncated = False

    def tag(self, source: str, values: list[str]) -> None:
        for value in values:
            truncated_value = value.encode("utf-8")[: self.max_value_bytes].decode(
                "utf-8", errors="ignore"
            )
            if not truncated_value:
                continue
            if truncated_value in self._entries:
                self._entries.move_to_end(truncated_value)
                continue
            self._entries[truncated_value] = source
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)
                self.truncated = True

    def values_for_source(self, source: str) -> list[str]:
        return [v for v, s in self._entries.items() if s == source]

    def find_matches(self, text: str) -> list[dict]:
        candidates = [text] + _decode_variants(text)
        matches: list[dict] = []
        seen_sources: set[str] = set()

        for candidate in candidates:
            for value, source in self._entries.items():
                if value and value in candidate and source not in seen_sources:
                    matches.append({"source": source, "value": value})
                    seen_sources.add(source)

        return matches

    @staticmethod
    def is_sink(tool_name: str, sink_patterns: list[str]) -> bool:
        return any(fnmatch.fnmatch(tool_name, pattern) for pattern in sink_patterns)

    @staticmethod
    def is_sensitive_source(name: str, source_patterns: list[str]) -> bool:
        return any(fnmatch.fnmatch(name, pattern) for pattern in source_patterns)
