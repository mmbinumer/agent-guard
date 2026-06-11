from __future__ import annotations

import json
import os
import sys
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

Verdict = Literal["allowed", "blocked", "warned", "error"]
RiskScore = Literal["low", "medium", "high"]


@dataclass
class AuditEvent:
    session_id: str
    tool: str
    server: str
    args_summary: str
    detections: list[dict]
    verdict: Verdict
    risk_score: RiskScore
    scan_skipped: str | None = None
    ts: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


_THREAD_LOCK = threading.Lock()


if sys.platform == "win32":
    import msvcrt

    def _flock_exclusive(fd: int) -> None:
        # msvcrt.LK_LOCK blocks for ~10s per attempt; retry until acquired.
        while True:
            try:
                msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
                return
            except OSError:
                continue

    def _flock_release(fd: int) -> None:
        try:
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
else:
    import fcntl

    def _flock_exclusive(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_EX)

    def _flock_release(fd: int) -> None:
        fcntl.flock(fd, fcntl.LOCK_UN)


_DEFAULT_MAX_BYTES = 50 * 1024 * 1024  # 50 MB before rotating


class AuditLogger:
    """JSONL audit log writer with cross-process append safety and size-based
    rotation.

    Concurrency: every line is written under an exclusive advisory file lock
    on a sibling `.lock` file (`fcntl.flock` on POSIX, `msvcrt.locking` on
    Windows) plus a process-local threading lock. Multiple `agent-guard`
    instances writing the same audit log will not interleave lines.

    Rotation: once the log exceeds `max_bytes`, it is renamed to
    `<path>.1` (replacing any prior rotation) before the next write. v1
    keeps only one rotated file — older history is discarded so disk usage
    stays bounded.
    """

    def __init__(self, path: str | Path, max_bytes: int = _DEFAULT_MAX_BYTES):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_bytes = max_bytes
        self._lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        # Seed a sentinel byte so msvcrt.locking has something to lock at
        # offset 0 even if the audit log itself is still empty.
        if not self._lock_path.exists():
            self._lock_path.write_bytes(b"\0")

    def log(self, event: AuditEvent) -> None:
        data = (json.dumps(asdict(event)) + "\n").encode("utf-8")
        with _THREAD_LOCK:
            lock_fd = os.open(self._lock_path, os.O_RDWR)
            try:
                _flock_exclusive(lock_fd)
                try:
                    self._rotate_if_needed(len(data))
                    fd = os.open(
                        self.path,
                        os.O_WRONLY | os.O_CREAT | os.O_APPEND,
                        0o600,
                    )
                    try:
                        os.write(fd, data)
                    finally:
                        os.close(fd)
                finally:
                    _flock_release(lock_fd)
            finally:
                os.close(lock_fd)

    def _rotate_if_needed(self, incoming_bytes: int) -> None:
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return
        if size + incoming_bytes <= self.max_bytes:
            return
        rotated = self.path.with_suffix(self.path.suffix + ".1")
        try:
            if rotated.exists():
                rotated.unlink()
            self.path.rename(rotated)
        except OSError:
            # Best-effort: another process may have rotated concurrently.
            pass
