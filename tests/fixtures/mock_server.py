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
from mcp.types import TextContent, Tool

app = Server("mock-server")

_FILES = {
    ".env": "API_KEY=sk-leakedvalue1234567890abcdefghijkl",
    "README.md": "This is a normal readme.",
}


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="echo",
            description="Echo text back",
            inputSchema={
                "type": "object",
                "properties": {"text": {"type": "string"}},
                "required": ["text"],
            },
        ),
        Tool(
            name="read_file",
            description="Read a file by path",
            inputSchema={
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "echo":
        return [TextContent(type="text", text=arguments["text"])]
    if name == "read_file":
        content = _FILES.get(arguments["path"], "")
        return [TextContent(type="text", text=content)]
    raise ValueError(f"Unknown tool: {name}")


async def main() -> None:
    async with stdio_server() as (read, write):
        await app.run(read, write, app.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
