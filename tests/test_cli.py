import json

from click.testing import CliRunner

from agent_guard.audit import AuditEvent, AuditLogger
from agent_guard.cli import main


def _write_events(audit_log_path):
    logger = AuditLogger(audit_log_path)
    logger.log(AuditEvent(
        session_id="s1", tool="fs.read_file", server="fs", args_summary="path=.env",
        detections=[], verdict="allowed", risk_score="low", scan_skipped=None,
    ))
    logger.log(AuditEvent(
        session_id="s1", tool="slack.post_message", server="slack", args_summary="...",
        detections=[{"type": "taint_leak", "rule": "external_sinks", "matched_source": "fs:.env", "action": "block"}],
        verdict="blocked", risk_score="high", scan_skipped=None,
    ))


def test_tail_prints_recent_events(tmp_path):
    audit_log = tmp_path / "audit.log"
    _write_events(audit_log)

    runner = CliRunner()
    result = runner.invoke(main, ["tail", "--log", str(audit_log), "--no-follow"])

    assert result.exit_code == 0
    assert "fs.read_file" in result.output
    assert "slack.post_message" in result.output
    assert "blocked" in result.output


def test_report_summarizes_counts(tmp_path):
    audit_log = tmp_path / "audit.log"
    _write_events(audit_log)

    runner = CliRunner()
    result = runner.invoke(main, ["report", "--log", str(audit_log)])

    assert result.exit_code == 0
    assert "allowed: 1" in result.output
    assert "blocked: 1" in result.output


def test_kill_sets_kill_switch_true(tmp_path):
    config_path = tmp_path / "agent-guard.yaml"
    config_path.write_text("""
servers:
  - name: fs
    command: ["x"]
kill_switch: false
""")

    runner = CliRunner()
    result = runner.invoke(main, ["kill", "--config", str(config_path)])

    assert result.exit_code == 0
    assert "kill_switch: true" in config_path.read_text()
