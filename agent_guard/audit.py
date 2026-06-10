from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

Verdict = Literal["allowed", "blocked", "warned"]
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


class AuditLogger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: AuditEvent) -> None:
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(asdict(event)) + "\n")
