from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from agent_guard.audit import AuditEvent, AuditLogger
from agent_guard.config import AgentGuardConfig
from agent_guard.detectors.dangerous import find_dangerous_commands
from agent_guard.detectors.injection import find_injection_markers
from agent_guard.detectors.secrets import find_secrets
from agent_guard.detectors.taint import TaintStore


@dataclass
class PreCallDecision:
    allowed: bool
    reason: str | None = None


@dataclass
class PostCallDecision:
    result_for_agent: Any
    detections: list[dict] = field(default_factory=list)


def _args_to_text(args: dict) -> str:
    return json.dumps(args, default=str)


def _result_to_text(result: Any) -> str:
    return result if isinstance(result, str) else json.dumps(result, default=str)


def _risk_score(detections: list[dict]) -> str:
    if any(d["action"] in ("block",) for d in detections):
        return "high"
    if any(d["action"] == "warn" for d in detections):
        return "medium"
    return "low"


class Pipeline:
    """Pre/post-call detection pipeline. One instance per agent session."""

    def __init__(
        self,
        config: AgentGuardConfig,
        audit: AuditLogger,
        taint: TaintStore,
        session_id: str,
    ):
        self.config = config
        self.audit = audit
        self.taint = taint
        self.session_id = session_id
        self._truncation_logged = False

    def _resolve_action(self, detection_type: str) -> str:
        return getattr(self.config.actions, detection_type)

    def _log(
        self,
        tool: str,
        server: str,
        args_summary: str,
        detections: list[dict],
        verdict: str,
        scan_skipped: str | None,
    ) -> None:
        self.audit.log(AuditEvent(
            session_id=self.session_id,
            tool=tool,
            server=server,
            args_summary=args_summary,
            detections=detections,
            verdict=verdict,
            risk_score=_risk_score(detections),
            scan_skipped=scan_skipped,
        ))

        if self.taint.truncated and not self._truncation_logged:
            self.audit.log(AuditEvent(
                session_id=self.session_id,
                tool=tool,
                server=server,
                args_summary="",
                detections=[{"type": "taint_store_truncated", "action": "warn"}],
                verdict="warned",
                risk_score="medium",
                scan_skipped=None,
            ))
            self._truncation_logged = True

    def pre_call(self, server: str, tool: str, args: dict) -> PreCallDecision:
        if self.config.kill_switch:
            self._log(
                tool, server, _args_to_text(args)[:200],
                [{"type": "kill_switch", "rule": "global", "action": "block"}],
                verdict="blocked", scan_skipped=None,
            )
            return PreCallDecision(allowed=False, reason="kill_switch")

        text = _args_to_text(args)
        scan_skipped = None
        detections: list[dict] = []

        for cmd in find_dangerous_commands(text):
            detections.append({
                "type": "dangerous_command", "rule": "dangerous_patterns",
                "matched": cmd, "action": self._resolve_action("dangerous_command"),
            })

        if len(text.encode("utf-8")) > self.config.limits.max_scan_bytes:
            scan_skipped = "size_limit"
        else:
            if self.taint.is_sink(tool, self.config.taint.external_sinks.tools):
                for match in self.taint.find_matches(text):
                    detections.append({
                        "type": "taint_leak", "rule": "external_sinks",
                        "matched_source": match["source"],
                        "action": self._resolve_action("taint_leak"),
                    })

            for _secret in find_secrets(text):
                detections.append({
                    "type": "secret_in_args", "rule": "secret_patterns",
                    "matched": "[REDACTED]", "action": self._resolve_action("secret_in_args"),
                })

        verdict, allowed = self._verdict_for(detections)
        self._log(tool, server, text[:200], detections, verdict, scan_skipped)

        return PreCallDecision(
            allowed=allowed,
            reason=None if allowed else detections[0]["type"],
        )

    def post_call(self, server: str, tool: str, args: dict, result: Any) -> PostCallDecision:
        text = _result_to_text(result)
        detections: list[dict] = []
        scan_skipped = None
        secrets_found: list[str] = []

        if len(text.encode("utf-8")) > self.config.limits.max_scan_bytes:
            scan_skipped = "size_limit"
        else:
            secrets_found = find_secrets(text)
            for _secret in secrets_found:
                detections.append({
                    "type": "secret_in_output", "rule": "secret_patterns",
                    "matched": "[REDACTED]", "action": self._resolve_action("secret_in_output"),
                })

            for marker in find_injection_markers(text):
                detections.append({
                    "type": "prompt_injection_marker", "rule": "injection_patterns",
                    "matched": marker, "action": self._resolve_action("prompt_injection_marker"),
                })

        # Taint tagging: if this read came from a sensitive source, tag values
        for path_or_table in (
            self.config.taint.sensitive_sources.files
            + self.config.taint.sensitive_sources.db_tables
        ):
            if (
                TaintStore.is_sensitive_source(str(args.get("path", "")), [path_or_table])
                or TaintStore.is_sensitive_source(str(args.get("table", "")), [path_or_table])
            ):
                source_label = f"{server}:{path_or_table}"
                if scan_skipped:
                    pass  # oversized: don't tag, per size-cap policy
                elif secrets_found:
                    self.taint.tag(source=source_label, values=secrets_found)
                elif len(text.encode("utf-8")) <= 512:
                    self.taint.tag(source=source_label, values=[text])

        verdict, _allowed = self._verdict_for(detections)
        self._log(tool, server, "[output]", detections, verdict, scan_skipped)

        return PostCallDecision(result_for_agent=result, detections=detections)

    def _verdict_for(self, detections: list[dict]) -> tuple[str, bool]:
        if not detections:
            return "allowed", True

        effective_actions = []
        for d in detections:
            action = d["action"]
            if self.config.mode == "audit-only" and action == "block":
                action = "warn"
            effective_actions.append(action)

        if "block" in effective_actions:
            return "blocked", False
        if "warn" in effective_actions:
            return "warned", True
        return "allowed", True
