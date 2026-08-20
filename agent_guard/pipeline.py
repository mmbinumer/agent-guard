from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from agent_guard.audit import AuditEvent, AuditLogger
from agent_guard.config import AgentGuardConfig
from agent_guard.detectors.dangerous import (
    find_dangerous_commands,
    find_path_traversal,
    find_sql_injection,
)
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


def _arg_string_values(args: dict) -> list[str]:
    return [v for v in args.values() if isinstance(v, str)]


def _redact(text: str, values: list[str]) -> str:
    # Replace longest values first so a shorter substring doesn't pre-empt a
    # longer secret. Empty strings are skipped to avoid an infinite expansion.
    for v in sorted({v for v in values if v}, key=len, reverse=True):
        text = text.replace(v, "[REDACTED]")
    return text


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
        parent_run_id: str | None = None,
    ):
        self.config = config
        self.audit = audit
        self.taint = taint
        self.session_id = session_id
        self.parent_run_id = parent_run_id
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
        result_hash: str | None = None,
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
            parent_run_id=self.parent_run_id,
            result_hash=result_hash,
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
                parent_run_id=self.parent_run_id,
            ))
            self._truncation_logged = True

    def pre_call(self, server: str, tool: str, args: dict) -> PreCallDecision:
        if self.config.kill_switch:
            # Args may contain secrets; don't echo them when we didn't scan.
            self._log(
                tool, server, "",
                [{"type": "kill_switch", "rule": "global", "action": "block"}],
                verdict="blocked", scan_skipped=None,
            )
            return PreCallDecision(allowed=False, reason="kill_switch")

        text = _args_to_text(args)
        scan_skipped = None
        detections: list[dict] = []
        sensitive_values: list[str] = []

        for cmd in find_dangerous_commands(text):
            detections.append({
                "type": "dangerous_command", "rule": "dangerous_patterns",
                "matched": cmd, "action": self._resolve_action("dangerous_command"),
            })

        # Heuristic arg tripwires: scan each string value (not the JSON blob) to
        # avoid escaping artifacts and cross-arg false matches.
        for value in _arg_string_values(args):
            for rule, matched in find_path_traversal(value):
                detections.append({
                    "type": "path_traversal", "rule": rule,
                    "matched": matched[:120], "action": self._resolve_action("path_traversal"),
                })
            for rule, matched in find_sql_injection(value):
                detections.append({
                    "type": "sql_injection", "rule": rule,
                    "matched": matched[:120], "action": self._resolve_action("sql_injection"),
                })

        if len(text.encode("utf-8")) > self.config.limits.max_scan_bytes:
            scan_skipped = "size_limit"
        else:
            if self.taint.is_sink(tool, self.config.taint.external_sinks.tools):
                matches = self.taint.find_matches(text)
                for match in matches:
                    detections.append({
                        "type": "taint_leak", "rule": "external_sinks",
                        "matched_source": match["source"],
                        "action": self._resolve_action("taint_leak"),
                    })
                    sensitive_values.append(match["value"])

                # A clean scan is only meaningful if we still hold all the
                # evidence. Once entries have been evicted we cannot claim the
                # call is clean, so report the unknown rather than passing it.
                if not matches and self.taint.truncated:
                    detections.append({
                        "type": "taint_unknown", "rule": "evidence_evicted",
                        "matched": "taint store evicted entries; scan is not conclusive",
                        "action": self._resolve_action("taint_unknown"),
                    })

            for secret in find_secrets(text):
                detections.append({
                    "type": "secret_in_args", "rule": "secret_patterns",
                    "matched": "[REDACTED]", "action": self._resolve_action("secret_in_args"),
                })
                sensitive_values.append(secret)

        verdict, allowed = self._verdict_for(detections)
        safe_summary = _redact(text, sensitive_values)[:200]
        self._log(tool, server, safe_summary, detections, verdict, scan_skipped)

        return PreCallDecision(
            allowed=allowed,
            reason=None if allowed else detections[0]["type"],
        )

    def _inspect_incoming(
        self,
        server: str,
        label: str,
        text: str,
        args_summary: str,
        source_values: list[str],
        source_patterns: list[str],
    ) -> list[dict]:
        """Scan data arriving from a downstream server, tag it if it came from
        a sensitive source, and log the result.

        Shared by tool results and resource reads: both are inbound data that
        can carry a secret, an injection marker, or a value worth tainting.
        They differ only in what identifies the source (`args` vs a URI) and
        which patterns mark it sensitive."""
        detections: list[dict] = []
        scan_skipped = None
        secrets_found: list[str] = []

        # Hashed before the size gate: an oversized result is exactly the one
        # a receipt still needs to identify, even though we did not scan it.
        result_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()

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

        for pattern in source_patterns:
            if any(
                TaintStore.is_sensitive_source(v, [pattern]) for v in source_values
            ):
                source_label = f"{server}:{pattern}"
                if scan_skipped:
                    pass  # oversized: don't tag, per size-cap policy
                elif secrets_found:
                    self.taint.tag(source=source_label, values=secrets_found)
                elif len(text.encode("utf-8")) <= self.config.limits.max_taint_value_bytes:
                    self.taint.tag(source=source_label, values=[text])

        verdict, _allowed = self._verdict_for(detections)
        self._log(label, server, args_summary, detections, verdict, scan_skipped, result_hash)
        return detections

    def post_call(self, server: str, tool: str, args: dict, result: Any) -> PostCallDecision:
        # Every string arg is matched against the source patterns, so we don't
        # depend on a tool naming its argument `path` or `table`.
        detections = self._inspect_incoming(
            server=server,
            label=tool,
            text=_result_to_text(result),
            args_summary="[output]",
            source_values=_arg_string_values(args),
            source_patterns=(
                self.config.taint.sensitive_sources.files
                + self.config.taint.sensitive_sources.db_tables
            ),
        )
        return PostCallDecision(result_for_agent=result, detections=detections)

    def post_read_resource(
        self, server: str, uri: str, contents: Any,
    ) -> PostCallDecision:
        """Inspect a resources/read result.

        Without this, a value reaching the agent through a resource is never
        tainted, so it can leave through a sink unnoticed - tool results were
        only ever one of the two ways data arrives."""
        text = _result_to_text(contents)
        # A URI can itself carry a credential (a token in a query string), so
        # the summary is redacted rather than logged verbatim.
        safe_uri = _redact(uri, find_secrets(uri))
        return PostCallDecision(
            result_for_agent=contents,
            detections=self._inspect_incoming(
                server=server,
                label="resources/read",
                text=text,
                args_summary=json.dumps({"uri": safe_uri})[:200],
                source_values=[uri],
                source_patterns=self.config.taint.sensitive_sources.uris,
            ),
        )

    def record_resource_listing_failure(self, server: str, error: BaseException) -> None:
        """Log a resource listing that failed for a reason other than the
        server simply not implementing resources. The proxy carries on with
        no resources for it, so this is the only signal that its resources
        are unguarded."""
        self._log(
            "resources/list", server, "",
            [{
                "type": "resource_listing_failed", "rule": "transport",
                "matched": f"{type(error).__name__}: {error}"[:200], "action": "warn",
            }],
            verdict="warned", scan_skipped=None,
        )

    def record_resource_collision(self, uri: str, servers: list[str]) -> None:
        """Log a URI claimed by several servers. Recorded at connect time so
        the conflict is visible up front, rather than surfacing later as an
        unexplained failed read."""
        self._log(
            "resources/list", ",".join(servers), json.dumps({"uri": uri})[:200],
            [{
                "type": "resource_uri_collision", "rule": "resource_routing",
                "matched": uri, "action": "warn",
            }],
            verdict="warned", scan_skipped=None,
        )

    def record_downstream_error(self, server: str, tool: str, error: BaseException) -> None:
        """Log an audit event when the downstream MCP server raises during a
        call we already authorized. Without this, the audit log shows the
        pre-call event but no resolution."""
        self._log(
            tool, server, "",
            [{
                "type": "downstream_error", "rule": "transport",
                "matched": f"{type(error).__name__}: {error}"[:200],
                "action": "warn",
            }],
            verdict="error",
            scan_skipped=None,
        )

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
