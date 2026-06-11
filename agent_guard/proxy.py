from __future__ import annotations

from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import TextContent, Tool

from agent_guard.config import AgentGuardConfig
from agent_guard.pipeline import Pipeline


class BlockedCallError(Exception):
    """Raised when the pipeline blocks a tool call."""


@dataclass
class _ConnectedServer:
    name: str
    session: ClientSession
    tools: list[Tool]


class AgentGuardProxy:
    """Aggregates one or more downstream MCP servers behind a single
    interface, routing tools/call through the detection Pipeline.

    Tool names are exposed as `<server_name>.<tool_name>`."""

    def __init__(self, config: AgentGuardConfig, pipeline: Pipeline):
        self.config = config
        self.pipeline = pipeline
        self._servers: dict[str, _ConnectedServer] = {}

    @asynccontextmanager
    async def connected(self):
        async with AsyncExitStack() as stack:
            for server_cfg in self.config.servers:
                params = StdioServerParameters(
                    command=server_cfg.command[0],
                    args=server_cfg.command[1:],
                )
                read, write = await stack.enter_async_context(stdio_client(params))
                session = await stack.enter_async_context(ClientSession(read, write))
                await session.initialize()

                tools_result = await session.list_tools()
                self._servers[server_cfg.name] = _ConnectedServer(
                    name=server_cfg.name, session=session, tools=tools_result.tools,
                )
            try:
                yield self
            finally:
                self._servers = {}

    async def list_tools(self) -> list[Tool]:
        aggregated: list[Tool] = []
        for server_name, server in self._servers.items():
            for tool in server.tools:
                aggregated.append(Tool(
                    name=f"{server_name}.{tool.name}",
                    description=tool.description,
                    inputSchema=tool.inputSchema,
                ))
        return aggregated

    def _resolve(self, qualified_name: str) -> tuple[str, str]:
        server_name, _, tool_name = qualified_name.partition(".")
        if server_name not in self._servers or not tool_name:
            raise ValueError(f"Unknown tool: {qualified_name}")
        return server_name, tool_name

    async def call_tool(self, qualified_name: str, arguments: dict) -> list[TextContent]:
        server_name, tool_name = self._resolve(qualified_name)

        decision = self.pipeline.pre_call(server=server_name, tool=qualified_name, args=arguments)
        if not decision.allowed:
            raise BlockedCallError(f"Blocked by Agent Guard: {decision.reason}")

        try:
            result = await self._servers[server_name].session.call_tool(tool_name, arguments)
        except Exception as exc:
            self.pipeline.record_downstream_error(
                server=server_name, tool=qualified_name, error=exc,
            )
            raise

        # Extract text for scanning, but return the original content blocks
        # so non-text content (images, embedded resources) isn't dropped.
        text_for_scan = "".join(
            block.text for block in result.content if isinstance(block, TextContent)
        )

        self.pipeline.post_call(
            server=server_name, tool=qualified_name, args=arguments, result=text_for_scan,
        )

        return list(result.content)

    def _build_mcp_server(self):
        """Construct an mcp.server.Server with handlers wired to this proxy's
        list_tools/call_tool, without running it."""
        from mcp.server import Server

        server = Server("agent-guard")

        @server.list_tools()
        async def _list_tools() -> list[Tool]:
            return await self.list_tools()

        @server.call_tool()
        async def _call_tool(name: str, arguments: dict) -> list[TextContent]:
            return await self.call_tool(name, arguments)

        return server

    async def serve_stdio(self) -> None:
        """Run Agent Guard as a stdio MCP server, exposing aggregated downstream
        tools to an upstream MCP client. Each tools/call is routed through
        self.call_tool (which applies the detection pipeline)."""
        from mcp.server.stdio import stdio_server

        server = self._build_mcp_server()
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
