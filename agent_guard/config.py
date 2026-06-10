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
    prompt_injection_marker: Action = "warn"


class SensitiveSources(BaseModel):
    files: list[str] = Field(
        default_factory=lambda: [".env", "*secret*", "*credentials*", "id_rsa*"]
    )
    db_tables: list[str] = Field(default_factory=list)


class ExternalSinks(BaseModel):
    tools: list[str] = Field(
        default_factory=lambda: ["http.*", "email.*", "slack.*", "*send*"]
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
