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
            "sensitive_sources": {"files": [".env"], "db_tables": [], "uris": ["*secret*"]},
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
async def test_list_resources_aggregates(tmp_path):
    proxy, _ = make_proxy(tmp_path)
    async with proxy.connected():
        resources = await proxy.list_resources()

    uris = {str(r.uri) for r in resources}
    assert "mock://docs/welcome" in uris


@pytest.mark.asyncio
async def test_read_resource_returns_contents(tmp_path):
    proxy, _ = make_proxy(tmp_path)
    async with proxy.connected():
        contents = await proxy.read_resource("mock://docs/welcome")

    assert "Welcome to the project" in contents[0].text


@pytest.mark.asyncio
async def test_read_resource_is_audited(tmp_path):
    proxy, audit_log = make_proxy(tmp_path)
    async with proxy.connected():
        await proxy.read_resource("mock://docs/welcome")

    log_text = audit_log.read_text()
    assert "resources/read" in log_text
    assert "mock://docs/welcome" in log_text


@pytest.mark.asyncio
async def test_unlisted_uri_routes_via_template(tmp_path):
    # Not in resources/list, but matches the server's declared template.
    proxy, _ = make_proxy(tmp_path)
    async with proxy.connected():
        contents = await proxy.read_resource("mock://pages/onboarding")

    assert "generated page for onboarding" in contents[0].text


@pytest.mark.asyncio
async def test_unroutable_uri_is_refused_without_contacting_servers(tmp_path):
    from agent_guard.resource_router import ResourceRoutingError

    proxy, _ = make_proxy(tmp_path)
    async with proxy.connected():
        with pytest.raises(ResourceRoutingError):
            await proxy.read_resource("unknown://nowhere/at/all")


@pytest.mark.asyncio
async def test_resource_taint_flows_to_sink_end_to_end(tmp_path):
    # The whole point: a value that entered via a resource, not a tool, is
    # still caught on the way out.
    proxy, _ = make_proxy(tmp_path)
    async with proxy.connected():
        await proxy.read_resource("mock://secrets/db")

        with pytest.raises(Exception):
            await proxy.call_tool(
                "mock__echo", {"text": "conn=postgres://user:pw-mock-31337@host/db"},
            )


@pytest.mark.asyncio
async def test_server_without_resources_is_not_an_error(tmp_path):
    # resources/* is optional in MCP. A server that omits it answers
    # "Method not found", which is expected, not a fault worth logging.
    from mcp.shared.exceptions import MCPError

    proxy, audit_log = make_proxy(tmp_path)

    class _NoResources:
        async def list_resources(self):
            raise MCPError(code=-32601, message="Method not found")

        async def list_resource_templates(self):
            raise MCPError(code=-32601, message="Method not found")

    resources, templates = await proxy._list_resources_safely("srv", _NoResources())

    assert (resources, templates) == ([], [])
    assert not audit_log.exists() or "resource_listing_failed" not in audit_log.read_text()


@pytest.mark.asyncio
async def test_unexpected_resource_listing_failure_is_logged(tmp_path):
    # A transient failure would otherwise leave a server that does have
    # resources registered with none, and later reads would fail with a
    # misleading "no server owns this URI".
    proxy, audit_log = make_proxy(tmp_path)

    class _Broken:
        async def list_resources(self):
            raise ConnectionResetError("pipe died")

        async def list_resource_templates(self):
            raise ConnectionResetError("pipe died")

    resources, templates = await proxy._list_resources_safely("srv", _Broken())

    assert (resources, templates) == ([], [])
    assert "resource_listing_failed" in audit_log.read_text()


def make_colliding_proxy(tmp_path):
    """Two servers exposing identical URIs - the same fixture mounted twice."""
    config = AgentGuardConfig.model_validate({
        "servers": [
            {"name": "a", "command": [sys.executable, "-m", "tests.fixtures.mock_server"]},
            {"name": "b", "command": [sys.executable, "-m", "tests.fixtures.mock_server"]},
        ],
    })
    audit_log = tmp_path / "audit.log"
    pipeline = Pipeline(
        config=config, audit=AuditLogger(audit_log),
        taint=TaintStore(max_value_bytes=512, max_entries=1000), session_id="sess-c",
    )
    return AgentGuardProxy(config=config, pipeline=pipeline), audit_log


@pytest.mark.asyncio
async def test_uri_collision_is_logged_at_connect(tmp_path):
    proxy, audit_log = make_colliding_proxy(tmp_path)
    async with proxy.connected():
        pass

    log_text = audit_log.read_text()
    assert "resource_uri_collision" in log_text
    assert "mock://docs/welcome" in log_text


@pytest.mark.asyncio
async def test_colliding_uri_read_is_refused(tmp_path):
    # Silently returning one server's copy would have the agent act on the
    # wrong content with no signal that a choice was even made.
    from agent_guard.resource_router import ResourceRoutingError

    proxy, _ = make_colliding_proxy(tmp_path)
    async with proxy.connected():
        with pytest.raises(ResourceRoutingError):
            await proxy.read_resource("mock://docs/welcome")


@pytest.mark.asyncio
async def test_served_mcp_server_exposes_resources(tmp_path):
    # The in-process API is not what a real client uses; the handlers have to
    # be wired into the served Server too.
    proxy, _ = make_proxy(tmp_path)
    async with proxy.connected():
        mcp_server = proxy._build_mcp_server()

        from mcp.types import PaginatedRequestParams, ReadResourceRequestParams

        entry = mcp_server.get_request_handler("resources/list")
        result = await entry.handler(None, PaginatedRequestParams())
        assert "mock://docs/welcome" in {str(r.uri) for r in result.resources}

        entry = mcp_server.get_request_handler("resources/read")
        result = await entry.handler(
            None, ReadResourceRequestParams(uri="mock://docs/welcome"),
        )
        assert "Welcome to the project" in result.contents[0].text


@pytest.mark.asyncio
async def test_build_mcp_server_wires_handlers(tmp_path):
    proxy, _ = make_proxy(tmp_path)
    async with proxy.connected():
        mcp_server = proxy._build_mcp_server()
        assert mcp_server.name == "agent-guard"

        from mcp.types import CallToolRequestParams, PaginatedRequestParams

        # The handlers ignore the per-request context (it only carries the
        # session and transport plumbing), so None stands in for it here.
        list_tools_entry = mcp_server.get_request_handler("tools/list")
        result = await list_tools_entry.handler(None, PaginatedRequestParams())
        tool_names = {t.name for t in result.tools}
        assert "mock__echo" in tool_names
        assert "mock__read_file" in tool_names

        call_tool_entry = mcp_server.get_request_handler("tools/call")
        result = await call_tool_entry.handler(
            None,
            CallToolRequestParams(name="mock__echo", arguments={"text": "hello"}),
        )
        assert result.is_error is False
        assert result.content[0].text == "hello"


@pytest.mark.asyncio
async def test_blocked_call_returns_tool_error_not_transport_error(tmp_path):
    """A block has to reach the agent as a readable is_error result. If it
    escaped the handler instead, the runner would turn it into a JSON-RPC
    error and take down the agent's turn rather than telling it why."""
    proxy, _ = make_proxy(tmp_path)
    async with proxy.connected():
        mcp_server = proxy._build_mcp_server()

        from mcp.types import CallToolRequestParams

        entry = mcp_server.get_request_handler("tools/call")
        result = await entry.handler(
            None,
            CallToolRequestParams(name="mock__echo", arguments={"text": "rm -rf /"}),
        )

    assert result.is_error is True
    assert "Blocked by Agent Guard" in result.content[0].text
