from __future__ import annotations

import functools
from contextlib import AsyncExitStack, asynccontextmanager
from dataclasses import dataclass, field

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.types import TextContent, Tool

from agent_guard.config import AgentGuardConfig
from agent_guard.pipeline import Pipeline
from agent_guard.resource_router import ResourceRouter


class BlockedCallError(Exception):
    """Raised when the pipeline blocks a tool call."""


_METHOD_NOT_FOUND = -32601


@dataclass
class _ConnectedServer:
    name: str
    session: ClientSession
    tools: list[Tool]
    resources: list = field(default_factory=list)
    resource_templates: list = field(default_factory=list)


class AgentGuardProxy:
    """Aggregates one or more downstream MCP servers behind a single
    interface, routing tools/call through the detection Pipeline.

    Tool names are exposed as `<server_name>.<tool_name>`."""

    def __init__(self, config: AgentGuardConfig, pipeline: Pipeline):
        self.config = config
        self.pipeline = pipeline
        self._servers: dict[str, _ConnectedServer] = {}
        self._resources = ResourceRouter()
        # The upstream client's session, captured the first time a handler
        # runs. Server-initiated requests arrive outside any handler, so
        # there is no request context to borrow one from at that moment.
        self._client_session = None

    @asynccontextmanager
    async def connected(self):
        async with AsyncExitStack() as stack:
            for server_cfg in self.config.servers:
                params = StdioServerParameters(
                    command=server_cfg.command[0],
                    args=server_cfg.command[1:],
                )
                read, write = await stack.enter_async_context(stdio_client(params))

                # Bound to the server name so a callback knows who called it;
                # without these the server-initiated direction is unwatched.
                name = server_cfg.name
                session = await stack.enter_async_context(ClientSession(
                    read, write,
                    sampling_callback=functools.partial(self._on_sampling, name),
                    elicitation_callback=functools.partial(self._on_elicitation, name),
                ))
                await session.initialize()

                tools_result = await session.list_tools()

                # Resources are optional; a server that doesn't implement them
                # must not stop the rest of the proxy from coming up.
                resources, templates = await self._list_resources_safely(
                    server_cfg.name, session,
                )

                self._servers[server_cfg.name] = _ConnectedServer(
                    name=server_cfg.name,
                    session=session,
                    tools=tools_result.tools,
                    resources=resources,
                    resource_templates=templates,
                )
                self._resources.register(
                    server_cfg.name,
                    uris=[str(r.uri) for r in resources],
                    templates=[t.uri_template for t in templates],
                )

            self._log_resource_collisions()
            try:
                yield self
            finally:
                self._servers = {}
                self._resources = ResourceRouter()

    def _remember_client_session(self, ctx) -> None:
        session = getattr(ctx, "session", None)
        if session is not None:
            self._client_session = session

    def _refuse(self, reason: str, detail: str):
        from mcp import types

        return types.ErrorData(code=types.INVALID_REQUEST, message=f"{reason}: {detail}")

    async def _on_sampling(self, server_name: str, context, params):
        """A downstream server asking the client's model to process something.

        Outbound by nature, so it is inspected as a sink before being passed
        up. Nothing here is forwarded until the pipeline has seen it."""
        from mcp import types

        text = " ".join(
            getattr(m.content, "text", "") or "" for m in params.messages
        )
        if params.system_prompt:
            text = f"{params.system_prompt}\n{text}"

        decision = self.pipeline.check_sampling(server=server_name, text=text)
        if not decision.allowed:
            return self._refuse("Blocked by Agent Guard", decision.reason)

        if self._client_session is None:
            # Allowed by policy, but there is nobody to forward to. Refusing
            # is the only honest answer: fabricating a completion would feed
            # the server a response the client never produced.
            self.pipeline.record_no_upstream_client(
                server=server_name, method="sampling/createMessage",
            )
            return self._refuse("Agent Guard has no upstream client", "sampling")

        return await self._client_session.create_message(
            messages=params.messages,
            max_tokens=params.max_tokens,
            system_prompt=params.system_prompt,
            temperature=params.temperature,
            stop_sequences=params.stop_sequences,
            model_preferences=params.model_preferences,
        )

    async def _on_elicitation(self, server_name: str, context, params):
        """A downstream server asking the client to put a question to the user."""
        schema = getattr(params, "requested_schema", None) or {}
        fields = list((schema.get("properties") or {}).keys())

        decision = self.pipeline.check_elicitation(
            server=server_name, message=params.message or "", schema_fields=fields,
        )
        if not decision.allowed:
            return self._refuse("Blocked by Agent Guard", decision.reason)

        if self._client_session is None:
            self.pipeline.record_no_upstream_client(
                server=server_name, method="elicitation/create",
            )
            return self._refuse("Agent Guard has no upstream client", "elicitation")

        return await self._client_session.elicit(
            message=params.message, requested_schema=schema,
        )

    async def _list_resources_safely(self, server_name: str, session) -> tuple[list, list]:
        """Resources and templates for a server, empty if it serves neither.

        `resources/*` is optional in MCP, so a server that omits it answers
        "Method not found" - expected, and passed over quietly. Any other
        failure is logged instead of swallowed: a server that does have
        resources would otherwise be registered with none, and later reads
        would fail with a misleading "no server owns this URI"."""
        async def _attempt(call, attribute):
            try:
                return getattr(await call(), attribute)
            except Exception as exc:
                if getattr(exc, "code", None) != _METHOD_NOT_FOUND:
                    self.pipeline.record_resource_listing_failure(
                        server=server_name, error=exc,
                    )
                return []

        return (
            await _attempt(session.list_resources, "resources"),
            await _attempt(session.list_resource_templates, "resource_templates"),
        )

    def _log_resource_collisions(self) -> None:
        """Surface URIs claimed by more than one server at startup, so the
        conflict is visible before a read fails."""
        for uri, owners in self._resources.collisions.items():
            self.pipeline.record_resource_collision(uri=uri, servers=owners)

    async def list_tools(self) -> list[Tool]:
        aggregated: list[Tool] = []
        for server_name, server in self._servers.items():
            for tool in server.tools:
                aggregated.append(Tool(
                    name=f"{server_name}__{tool.name}",
                    description=tool.description,
                    input_schema=tool.input_schema,
                ))
        return aggregated

    def _resolve(self, qualified_name: str) -> tuple[str, str]:
        # Tool names must match ^[a-zA-Z0-9_-]{1,64}$ for MCP clients (no
        # dots), so server and tool name are joined with "__". Match against
        # known server names rather than splitting blindly, since either
        # part may itself contain underscores.
        for server_name in self._servers:
            prefix = f"{server_name}__"
            if qualified_name.startswith(prefix):
                tool_name = qualified_name[len(prefix):]
                if tool_name:
                    return server_name, tool_name
        raise ValueError(f"Unknown tool: {qualified_name}")

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

    async def list_resources(self) -> list:
        """Resources from every downstream server, URIs unchanged.

        Unlike tools these are not renamed: a URI carries scheme semantics,
        and rewriting it would change what the client displays. Ownership is
        tracked separately by the router."""
        aggregated: list = []
        for server in self._servers.values():
            aggregated.extend(server.resources)
        return aggregated

    async def list_resource_templates(self) -> list:
        aggregated: list = []
        for server in self._servers.values():
            aggregated.extend(server.resource_templates)
        return aggregated

    async def read_resource(self, uri: str) -> list:
        # Raises rather than probing each server in turn: the URI may itself
        # be sensitive, and asking uninvolved servers who owns it would leak
        # that path across a boundary this proxy exists to protect.
        server_name = self._resources.resolve(uri)

        try:
            result = await self._servers[server_name].session.read_resource(uri)
        except Exception as exc:
            self.pipeline.record_downstream_error(
                server=server_name, tool=f"resources/read {uri}", error=exc,
            )
            raise

        text_for_scan = "".join(
            getattr(block, "text", "") or "" for block in result.contents
        )
        self.pipeline.post_read_resource(
            server=server_name, uri=uri, contents=text_for_scan,
        )
        return list(result.contents)

    def _build_mcp_server(self):
        """Construct an mcp.server.Server with handlers wired to this proxy's
        list_tools/call_tool, without running it."""
        from mcp import types
        from mcp.server import Server

        async def _list_tools(ctx, params) -> types.ListToolsResult:
            self._remember_client_session(ctx)
            return types.ListToolsResult(tools=await self.list_tools())

        async def _call_tool(ctx, params) -> types.CallToolResult:
            self._remember_client_session(ctx)
            try:
                content = await self.call_tool(params.name, params.arguments or {})
            except Exception as exc:
                # A block (or a downstream failure) has to reach the agent as a
                # readable tool result, not a JSON-RPC transport error that
                # tears down its turn. mcp 1.x's @call_tool decorator wrapped
                # handlers this way; the 2.x callback hands exceptions to the
                # runner, which converts them to protocol errors - so the
                # is_error result is built here instead.
                return types.CallToolResult(
                    content=[types.TextContent(type="text", text=str(exc))],
                    is_error=True,
                )
            return types.CallToolResult(content=content)

        async def _list_resources(ctx, params) -> types.ListResourcesResult:
            self._remember_client_session(ctx)
            return types.ListResourcesResult(resources=await self.list_resources())

        async def _list_resource_templates(ctx, params) -> types.ListResourceTemplatesResult:
            return types.ListResourceTemplatesResult(
                resource_templates=await self.list_resource_templates(),
            )

        async def _read_resource(ctx, params) -> types.ReadResourceResult:
            self._remember_client_session(ctx)
            return types.ReadResourceResult(
                contents=await self.read_resource(str(params.uri)),
            )

        return Server(
            "agent-guard",
            on_list_tools=_list_tools,
            on_call_tool=_call_tool,
            on_list_resources=_list_resources,
            on_list_resource_templates=_list_resource_templates,
            on_read_resource=_read_resource,
        )

    async def serve_stdio(self) -> None:
        """Run Agent Guard as a stdio MCP server, exposing aggregated downstream
        tools to an upstream MCP client. Each tools/call is routed through
        self.call_tool (which applies the detection pipeline)."""
        from mcp.server.stdio import stdio_server

        server = self._build_mcp_server()
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())
