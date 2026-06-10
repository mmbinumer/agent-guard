import json

from agent_guard.audit import AuditLogger, AuditEvent


def test_log_event_writes_jsonl_line(tmp_path):
    log_path = tmp_path / "audit.log"
    logger = AuditLogger(log_path)

    event = AuditEvent(
        session_id="sess-1",
        tool="slack.post_message",
        server="slack",
        args_summary="channel=#general body=...",
        detections=[
            {"type": "taint_leak", "rule": "external_sinks", "matched_source": ".env", "action": "block"}
        ],
        verdict="blocked",
        risk_score="high",
        scan_skipped=None,
    )

    logger.log(event)

    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 1

    record = json.loads(lines[0])
    assert record["session_id"] == "sess-1"
    assert record["tool"] == "slack.post_message"
    assert record["verdict"] == "blocked"
    assert record["risk_score"] == "high"
    assert record["detections"][0]["type"] == "taint_leak"
    assert "ts" in record


def test_log_appends_multiple_events(tmp_path):
    log_path = tmp_path / "audit.log"
    logger = AuditLogger(log_path)

    for i in range(3):
        logger.log(AuditEvent(
            session_id="sess-1",
            tool=f"tool.{i}",
            server="fs",
            args_summary="",
            detections=[],
            verdict="allowed",
            risk_score="low",
            scan_skipped=None,
        ))

    lines = log_path.read_text().strip().splitlines()
    assert len(lines) == 3


def test_log_creates_parent_directory(tmp_path):
    log_path = tmp_path / "nested" / "dir" / "audit.log"
    logger = AuditLogger(log_path)

    logger.log(AuditEvent(
        session_id="sess-1", tool="t", server="s", args_summary="",
        detections=[], verdict="allowed", risk_score="low", scan_skipped=None,
    ))

    assert log_path.exists()
