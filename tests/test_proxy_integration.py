import sys

import pytest

from agent_guard.audit import AuditLogger
from agent_guard.config import AgentGuardConfig
from agent_guard.detectors.taint import TaintStore
from agent_guard.pipeline import Pipeline
from agent_guard.proxy import AgentGuardProxy


def make_proxy(tmp_path, mode="enforce"):
    config = AgentGuardConfig.model_validate({
        "servers": [
            {"name": "mock", "command": [sys.executable, "-m", "tests.fixtures.mock_server"]},
        ],
        "mode": mode,
        "actions": {
            "dangerous_command": "block",
            "secret_in_args": "block",
            "secret_in_output": "redact",
            "taint_leak": "block",
            "prompt_injection_marker": "warn",
        },
        "taint": {
            "sensitive_sources": {"files": [".env"], "db_tables": []},
            "external_sinks": {"tools": ["mock__echo"]},
        },
        "limits": {"max_scan_bytes": 4096, "max_taint_value_bytes": 512, "max_taint_entries": 1000},
        "kill_switch": False,
    })
    audit_log = tmp_path / "audit.log"
    logger = AuditLogger(audit_log)
    taint_store = TaintStore(
        max_value_bytes=config.limits.max_taint_value_bytes,
        max_entries=config.limits.max_taint_entries,
    )
    pipeline = Pipeline(config=config, audit=logger, taint=taint_store, session_id="sess-1")
    proxy = AgentGuardProxy(config=config, pipeline=pipeline)
    return proxy, audit_log


@pytest.mark.asyncio
async def test_list_tools_aggregates_with_server_prefix(tmp_path):
    proxy, _ = make_proxy(tmp_path)
    async with proxy.connected():
        tools = await proxy.list_tools()

    names = {t.name for t in tools}
    assert "mock__echo" in names
    assert "mock__read_file" in names


@pytest.mark.asyncio
async def test_safe_call_passes_through(tmp_path):
    proxy, audit_log = make_proxy(tmp_path)
    async with proxy.connected():
        result = await proxy.call_tool("mock__echo", {"text": "hello"})

    assert result[0].text == "hello"


@pytest.mark.asyncio
async def test_dangerous_call_blocked(tmp_path):
    proxy, audit_log = make_proxy(tmp_path)
    async with proxy.connected():
        with pytest.raises(Exception):
            await proxy.call_tool("mock__echo", {"text": "rm -rf /"})


@pytest.mark.asyncio
async def test_taint_leak_blocked_end_to_end(tmp_path):
    proxy, audit_log = make_proxy(tmp_path)
    async with proxy.connected():
        # Read the sensitive file -> tags taint store with the secret inside
        await proxy.call_tool("mock__read_file", {"path": ".env"})

        # Try to echo (configured as a sink) the leaked secret
        with pytest.raises(Exception):
            await proxy.call_tool(
                "mock__echo",
                {"text": "the key is sk-leakedvalue1234567890abcdefghijkl"},
            )


@pytest.mark.asyncio
async def test_audit_only_mode_allows_but_logs(tmp_path):
    proxy, audit_log = make_proxy(tmp_path, mode="audit-only")
    async with proxy.connected():
        result = await proxy.call_tool("mock__echo", {"text": "rm -rf /"})

    assert result[0].text == "rm -rf /"
    log_text = audit_log.read_text()
    assert '"verdict": "warned"' in log_text


@pytest.mark.asyncio
async def test_multi_block_result_preserves_all_blocks(tmp_path):
    proxy, _ = make_proxy(tmp_path)
    async with proxy.connected():
        result = await proxy.call_tool("mock__multi_block", {})

    assert [block.text for block in result] == ["first", "second", "third"]


@pytest.mark.asyncio
async def test_build_mcp_server_wires_handlers(tmp_path):
    proxy, _ = make_proxy(tmp_path)
    async with proxy.connected():
        mcp_server = proxy._build_mcp_server()
        assert mcp_server.name == "agent-guard"

        from mcp.types import ListToolsRequest, CallToolRequest

        list_tools_handler = mcp_server.request_handlers[ListToolsRequest]
        result = await list_tools_handler(ListToolsRequest(method="tools/list"))
        tool_names = {t.name for t in result.root.tools}
        assert "mock__echo" in tool_names
        assert "mock__read_file" in tool_names

        call_tool_handler = mcp_server.request_handlers[CallToolRequest]
        result = await call_tool_handler(
            CallToolRequest(
                method="tools/call",
                params={"name": "mock__echo", "arguments": {"text": "hello"}},
            )
        )
        content = result.root.content
        assert content[0].text == "hello"
