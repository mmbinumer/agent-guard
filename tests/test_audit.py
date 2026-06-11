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


def _evt(i: int) -> AuditEvent:
    return AuditEvent(
        session_id="s", tool=f"t{i}", server="srv", args_summary="x" * 100,
        detections=[], verdict="allowed", risk_score="low", scan_skipped=None,
    )


def test_log_rotates_when_size_exceeded(tmp_path):
    log_path = tmp_path / "audit.log"
    logger = AuditLogger(log_path, max_bytes=500)

    for i in range(20):
        logger.log(_evt(i))

    rotated = log_path.with_suffix(log_path.suffix + ".1")
    assert rotated.exists(), "rotation file should be created once size cap is hit"
    assert log_path.stat().st_size <= 500 + 256, "live log should be near or under cap"


def test_concurrent_writes_do_not_interleave(tmp_path):
    import threading

    log_path = tmp_path / "audit.log"
    logger = AuditLogger(log_path)

    def writer(thread_id: int):
        for i in range(50):
            logger.log(AuditEvent(
                session_id=f"s{thread_id}", tool=f"t{i}", server="srv",
                args_summary="x" * 200,
                detections=[], verdict="allowed", risk_score="low",
                scan_skipped=None,
            ))

    threads = [threading.Thread(target=writer, args=(tid,)) for tid in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    lines = log_path.read_text().splitlines()
    assert len(lines) == 8 * 50
    for line in lines:
        # Every line must be a valid complete JSON object — interleaved
        # writes would corrupt one of these.
        json.loads(line)
