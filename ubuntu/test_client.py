"""
Run from the repository root:
    uv run examples/snippets/clients/streamable_basic.py
"""
import asyncio
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async def run_test_commands(session):
    # List available tools
    tools = await session.list_tools()
    print(f"Available tools: {[tool.name for tool in tools.tools]}")

    tool_names = {tool.name for tool in tools.tools}

    # Test 1: get_system_info (no arguments)
    if "get_system_info" in tool_names:
        print("\nRunning get_system_info command...")
        result = await session.call_tool(name="get_system_info", arguments={})
        print("System info result:", result)

    # Test 2: execute_command (run simple shell command)
    if "execute_command" in tool_names:
        print("\nRunning execute_command with 'echo Hello MCP'...")
        exec_result = await session.call_tool(
            name="execute_command",
            arguments={"command": "echo Hello MCP"},  # assuming the argument expects `command` key
        )
        print("execute_command result:", exec_result)

    # Test 3: list_directory (list current directory)
    if "list_directory" in tool_names:
        print("\nRunning list_directory on path '/home' ...")
        list_result = await session.call_tool(
            name="list_directory",
            arguments={"path": "/home"},
        )
        print("list_directory result:", list_result)

    # Test 4: read_file (read this script itself or a sample file)
    if "read_file" in tool_names:
        print("\nRunning read_file on this script...")
        try:
            read_result = await session.call_tool(
                name="read_file",
                arguments={"path": "examples/snippets/clients/streamable_basic.py"},
            )
            print("read_file result (start):", read_result[:200] if isinstance(read_result, str) else read_result)
        except Exception as e:
            print(f"Error reading file: {e}")

    # Test 5: write_file (write a test file, then read it back)
    if "write_file" in tool_names and "read_file" in tool_names:
        test_path = "/tmp/mcp_test_file.txt"
        test_content = "Hello from MCP test client!"

        print(f"\nRunning write_file to path {test_path} ...")
        write_result = await session.call_tool(
            name="write_file",
            arguments={"path": test_path, "contents": test_content},
        )
        print("write_file result:", write_result)

        print("Reading back the written file...")
        read_back = await session.call_tool(
            name="read_file",
            arguments={"path": test_path},
        )
        print("Read back content:", read_back)
async def main():
    # Connect to a streamable HTTP server
    async with streamablehttp_client("http://127.0.0.1:9000/mcp") as (
        read_stream,
        write_stream,
        _,
    ):
        # Create a session using the client streams
        async with ClientSession(read_stream, write_stream) as session:
            # Initialize the connection
            await session.initialize()
            # Run the extended tests for commands
            await run_test_commands(session)

if __name__ == "__main__":
    asyncio.run(main())