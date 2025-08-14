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
        await asyncio.sleep(5)
 # 测试 GUI 工具 - 移动鼠标

    if "move_to" in tool_names:
        print("\n[GUI 测试] 移动鼠标到 (300, 300)")
        await session.call_tool(name="move_to", arguments={"x": 640, "y": 780})
        print("✅ 鼠标已移动")
        await asyncio.sleep(1) # 暂停以便观察

    if "click" in tool_names:
        print("\n[GUI 测试] 在当前位置单击鼠标左键")
        await session.call_tool(name="click", arguments={})
        print("✅ 已单击")
        await asyncio.sleep(1)

    if "right_click" in tool_names:
        print("\n[GUI 测试] 移动鼠标到 (500, 300) 并右击")
        await session.call_tool(name="move_to", arguments={"x": 500, "y": 300})
        await session.call_tool(name="right_click", arguments={})
        print("✅ 已右击 (应该会看到一个上下文菜单)")
        await asyncio.sleep(2) # 等待菜单出现
        await session.call_tool(name="press", arguments={"key": "escape"}) # 按 ESC 关闭菜单
        print("✅ 已按 ESC 关闭菜单")
        await asyncio.sleep(1)

    if "type" in tool_names:
        # 为了看到打字效果，我们先点击一下桌面
        await session.call_tool(name="click", arguments={"x": 100, "y": 100})
        
        print("\n[GUI 测试] 输入一段文本")
        await session.call_tool(
            name="type",
            arguments={"text": "Hello, this is your MCP agent typing!"}
        )
        print("✅ 已输入文本")
        await asyncio.sleep(1)

    if "press" in tool_names:
        print("\n[GUI 测试] 按下 'enter' 键")
        await session.call_tool(name="press", arguments={"key": "enter"})
        print("✅ 已按 Enter")
        await asyncio.sleep(1)

    import base64  # 1. 导入 base64 模块

    import json # 可能会用到，先导入

    if "get_screenshot" in tool_names:
        print("\n[GUI 测试] 捕获当前屏幕截图")
        
        # 1. 调用工具并接收返回的完整对象
        tool_response = await session.call_tool(name="get_screenshot", arguments={})

        # 2. 从返回的对象中提取出 'result' 字段的值
        #    这才是我们需要的 Base64 字符串
        #    通常 structuredContent 是一个字典
        screenshot_base64_string = tool_response.structuredContent['result']
        
        # 3. 后续的逻辑保持不变，现在 isinstance 判断会成功
        if isinstance(screenshot_base64_string, str) and len(screenshot_base64_string) > 100:
            try:
                # 将 Base64 字符串解码回原始的二进制数据
                screenshot_bytes = base64.b64decode(screenshot_base64_string)
                
                output_path = "screenshot_test.png"
                with open(output_path, "wb") as f:
                    # 将解码后的二进制数据写入文件
                    f.write(screenshot_bytes)
                print(f"✅ 截图成功！图像已从 Base64 字符串还原并保存到 '{output_path}' 文件中。")
            except base64.binascii.Error as e:
                print(f"❌ 截图失败。解码 Base64 字符串时出错: {e}")
                print(f"收到的数据片段: {screenshot_base64_string[:100]}...")
        else:
            print(f"❌ 截图失败。从工具返回的对象中未能提取出有效的 Base64 字符串。")
            print(f"收到的完整对象是: {tool_response}")
        
    print("\n--- 所有测试完成 ---")
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