from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field

Action = Literal["block", "redact", "warn", "allow"]
Mode = Literal["enforce", "audit-only"]


class ServerConfig(BaseModel):
    name: str
    command: list[str]


class ActionsConfig(BaseModel):
    dangerous_command: Action = "block"
    secret_in_args: Action = "block"
    secret_in_output: Action = "redact"
    taint_leak: Action = "block"
    # Taint evidence was evicted, so a clean scan on a sink call proves nothing.
    # Fail stricter rather than silently treating the call as clean.
    taint_unknown: Action = "warn"
    prompt_injection_marker: Action = "warn"
    # Heuristic tripwires on inbound args - warn by default (false-positive prone).
    path_traversal: Action = "warn"
    sql_injection: Action = "warn"
    # Server-initiated calls. A sampling request is an outbound channel, so a
    # tainted value in one is exfiltration; elicitation is the only surface
    # where a server addresses the user, so it is the phishing route.
    sampling_leak: Action = "block"
    elicitation_phishing: Action = "block"


class SensitiveSources(BaseModel):
    files: list[str] = Field(
        default_factory=lambda: [".env", "*secret*", "*credentials*", "id_rsa*"]
    )
    db_tables: list[str] = Field(default_factory=list)
    # Resources are identified by URI, so these need their own patterns: the
    # file patterns above do not match ("...*.env" vs a bare ".env").
    uris: list[str] = Field(
        default_factory=lambda: [
            "*.env", "*secret*", "*credential*", "*id_rsa*", "vault:*",
        ]
    )


class ExternalSinks(BaseModel):
    tools: list[str] = Field(
        # Tool names are aggregated as "<server>__<tool>", so sink patterns
        # must use that form. Dot-separated patterns match nothing.
        default_factory=lambda: ["http__*", "email__*", "slack__*", "*send*", "*post*"]
    )


class TaintConfig(BaseModel):
    sensitive_sources: SensitiveSources = Field(default_factory=SensitiveSources)
    external_sinks: ExternalSinks = Field(default_factory=ExternalSinks)


class LimitsConfig(BaseModel):
    max_scan_bytes: int = 262144
    max_taint_value_bytes: int = 512
    max_taint_entries: int = 1000


class AgentGuardConfig(BaseModel):
    servers: list[ServerConfig]
    mode: Mode = "enforce"
    actions: ActionsConfig = Field(default_factory=ActionsConfig)
    taint: TaintConfig = Field(default_factory=TaintConfig)
    limits: LimitsConfig = Field(default_factory=LimitsConfig)
    kill_switch: bool = False


def load_config(path: str | Path) -> AgentGuardConfig:
    with open(path) as f:
        raw = yaml.safe_load(f) or {}
    return AgentGuardConfig.model_validate(raw)
