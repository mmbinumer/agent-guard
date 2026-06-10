import json

from agent_guard.audit import AuditLogger
from agent_guard.config import AgentGuardConfig
from agent_guard.detectors.taint import TaintStore
from agent_guard.pipeline import Pipeline


def make_pipeline(tmp_path, **overrides):
    config_dict = {
        "servers": [{"name": "fs", "command": ["x"]}],
        "mode": "enforce",
        "actions": {
            "dangerous_command": "block",
            "secret_in_args": "block",
            "secret_in_output": "redact",
            "taint_leak": "block",
            "prompt_injection_marker": "warn",
        },
        "taint": {
            "sensitive_sources": {"files": [".env"], "db_tables": []},
            "external_sinks": {"tools": ["http.*", "slack.*"]},
        },
        "limits": {"max_scan_bytes": 1024, "max_taint_value_bytes": 512, "max_taint_entries": 1000},
        "kill_switch": False,
    }
    config_dict.update(overrides)
    config = AgentGuardConfig.model_validate(config_dict)

    audit_log = tmp_path / "audit.log"
    logger = AuditLogger(audit_log)
    taint_store = TaintStore(
        max_value_bytes=config.limits.max_taint_value_bytes,
        max_entries=config.limits.max_taint_entries,
    )
    pipeline = Pipeline(config=config, audit=logger, taint=taint_store, session_id="sess-1")
    return pipeline, audit_log


def last_log_record(audit_log):
    lines = audit_log.read_text().strip().splitlines()
    return json.loads(lines[-1])


def test_dangerous_command_blocked(tmp_path):
    pipeline, audit_log = make_pipeline(tmp_path)

    decision = pipeline.pre_call(
        server="fs", tool="shell.exec", args={"command": "rm -rf /"}
    )

    assert decision.allowed is False
    record = last_log_record(audit_log)
    assert record["verdict"] == "blocked"
    assert record["detections"][0]["type"] == "dangerous_command"


def test_secret_in_args_blocked(tmp_path):
    pipeline, audit_log = make_pipeline(tmp_path)

    decision = pipeline.pre_call(
        server="fs", tool="http.post",
        args={"body": "key=AKIAIOSFODNN7EXAMPLE"},
    )

    assert decision.allowed is False
    record = last_log_record(audit_log)
    assert record["detections"][0]["type"] == "secret_in_args"


def test_safe_call_allowed(tmp_path):
    pipeline, audit_log = make_pipeline(tmp_path)

    decision = pipeline.pre_call(
        server="fs", tool="fs.read_file", args={"path": "README.md"}
    )

    assert decision.allowed is True
    record = last_log_record(audit_log)
    assert record["verdict"] == "allowed"
    assert record["risk_score"] == "low"


def test_taint_tagging_then_leak_blocked(tmp_path):
    pipeline, audit_log = make_pipeline(tmp_path)

    # Read a sensitive file containing a secret -> tags taint store
    pipeline.post_call(
        server="fs", tool="fs.read_file", args={"path": ".env"},
        result="API_KEY=sk-leakedvalue1234567890abcdefghijkl",
    )

    # Now try to send that value to an external sink
    decision = pipeline.pre_call(
        server="fs", tool="slack.post_message",
        args={"body": "here is the key sk-leakedvalue1234567890abcdefghijkl"},
    )

    assert decision.allowed is False
    record = last_log_record(audit_log)
    assert record["detections"][0]["type"] == "taint_leak"


def test_secret_in_output_redacted_in_log_only(tmp_path):
    pipeline, audit_log = make_pipeline(tmp_path)

    result_text = "AKIAIOSFODNN7EXAMPLE"
    decision = pipeline.post_call(
        server="fs", tool="fs.read_file", args={"path": "notes.txt"}, result=result_text,
    )

    # Agent-facing result is unchanged
    assert decision.result_for_agent == result_text

    record = last_log_record(audit_log)
    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(record)
    assert record["detections"][0]["type"] == "secret_in_output"
    assert record["detections"][0]["action"] == "redact"


def test_audit_only_mode_does_not_block(tmp_path):
    pipeline, audit_log = make_pipeline(tmp_path, mode="audit-only")

    decision = pipeline.pre_call(
        server="fs", tool="shell.exec", args={"command": "rm -rf /"}
    )

    assert decision.allowed is True
    record = last_log_record(audit_log)
    assert record["verdict"] == "warned"
    assert record["detections"][0]["action"] == "block"  # would-have-been action


def test_kill_switch_blocks_everything(tmp_path):
    pipeline, audit_log = make_pipeline(tmp_path, kill_switch=True)

    decision = pipeline.pre_call(
        server="fs", tool="fs.read_file", args={"path": "README.md"}
    )

    assert decision.allowed is False
    record = last_log_record(audit_log)
    assert record["detections"][0]["type"] == "kill_switch"


def test_oversized_payload_skips_scan(tmp_path):
    pipeline, audit_log = make_pipeline(tmp_path)

    big_payload = "AKIAIOSFODNN7EXAMPLE " + ("x" * 2000)  # > max_scan_bytes=1024
    decision = pipeline.pre_call(
        server="fs", tool="http.post", args={"body": big_payload}
    )

    assert decision.allowed is True
    record = last_log_record(audit_log)
    assert record["scan_skipped"] == "size_limit"
