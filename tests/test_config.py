import pytest
from agent_guard.config import load_config, AgentGuardConfig


MINIMAL_YAML = """
servers:
  - name: fs
    command: ["mcp-server-filesystem", "/tmp"]

mode: enforce

actions:
  dangerous_command: block
  secret_in_args: block
  secret_in_output: redact
  taint_leak: block
  prompt_injection_marker: warn

taint:
  sensitive_sources:
    files: [".env", "*secret*"]
    db_tables: ["users"]
  external_sinks:
    tools: ["http.*", "email.*"]

limits:
  max_scan_bytes: 262144
  max_taint_value_bytes: 512
  max_taint_entries: 1000

kill_switch: false
"""


def test_load_minimal_config(tmp_path):
    config_path = tmp_path / "agent-guard.yaml"
    config_path.write_text(MINIMAL_YAML)

    config = load_config(config_path)

    assert isinstance(config, AgentGuardConfig)
    assert config.mode == "enforce"
    assert config.servers[0].name == "fs"
    assert config.servers[0].command == ["mcp-server-filesystem", "/tmp"]
    assert config.actions.dangerous_command == "block"
    assert config.actions.secret_in_output == "redact"
    assert config.taint.sensitive_sources.files == [".env", "*secret*"]
    assert config.taint.external_sinks.tools == ["http.*", "email.*"]
    assert config.limits.max_scan_bytes == 262144
    assert config.kill_switch is False


def test_load_config_applies_defaults(tmp_path):
    config_path = tmp_path / "agent-guard.yaml"
    config_path.write_text("""
servers:
  - name: fs
    command: ["mcp-server-filesystem", "/tmp"]
""")

    config = load_config(config_path)

    assert config.mode == "enforce"
    assert config.actions.dangerous_command == "block"
    assert config.actions.secret_in_output == "redact"
    assert config.actions.prompt_injection_marker == "warn"
    assert config.limits.max_scan_bytes == 262144
    assert config.limits.max_taint_value_bytes == 512
    assert config.limits.max_taint_entries == 1000
    assert config.kill_switch is False
    assert config.taint.sensitive_sources.files == [".env", "*secret*", "*credentials*", "id_rsa*"]
    assert config.taint.external_sinks.tools == ["http.*", "email.*", "slack.*", "*send*"]


def test_invalid_action_value_rejected(tmp_path):
    config_path = tmp_path / "agent-guard.yaml"
    config_path.write_text("""
servers:
  - name: fs
    command: ["mcp-server-filesystem", "/tmp"]
actions:
  dangerous_command: explode
""")

    with pytest.raises(ValueError):
        load_config(config_path)
