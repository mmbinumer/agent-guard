"""Minimal stdio MCP server for integration tests.

Run as: python -m tests.fixtures.mock_server
Exposes two tools:
  - echo(text: str) -> str: returns text unchanged
  - read_file(path: str) -> str: returns a canned value for known paths,
    used to simulate reading a sensitive file (.env) containing a secret.
"""
from __future__ import annotations

import asyncio

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import CallToolResult, ListToolsResult, TextContent, Tool

_FILES = {
    ".env": "API_KEY=sk-leakedvalue1234567890abcdefghijkl",
    "README.md": "This is a normal readme.",
}


async def list_tools(ctx, params) -> ListToolsResult:
    return ListToolsResult(tools=[
        Tool(
            name="echo",
            description="Echo text back",
            input_schema={
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
        ),
        Tool(
            name="read_file",
            description="Read a file by path",
            input_schema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        ),
        Tool(
            name="multi_block",
            description="Return multiple text blocks",
            input_schema={"type": "object", "properties": {}},
        ),
    ])


async def call_tool(ctx, params) -> CallToolResult:
    name = params.name
    arguments = params.arguments or {}
    if name == "echo":
        return CallToolResult(content=[TextContent(type="text", text=arguments["text"])])
    if name == "read_file":
        content = _FILES.get(arguments["path"], "")
        return CallToolResult(content=[TextContent(type="text", text=content)])
    if name == "multi_block":
        return CallToolResult(content=[
            TextContent(type="text", text="first"),
            TextContent(type="text", text="second"),
            TextContent(type="text", text="third"),
        ])
    raise ValueError(f"Unknown tool: {name}")


app = Server("mock-server", on_list_tools=list_tools, on_call_tool=call_tool)


async def main() -> None:
    async with stdio_server() as (read, write):
        await app.run(read, write, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
