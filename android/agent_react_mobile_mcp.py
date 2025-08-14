import os
import json
import asyncio
from contextlib import AsyncExitStack
from typing import List, Dict, Any

from dotenv import load_dotenv
from openai import OpenAI

from mcp import ClientSession
from mcp.client.sse import sse_client


SYSTEM_PROMPT = """You are a ReAct-style agent that uses Model Context Protocol (MCP) tools. Your goal is to accomplish the user's intent on a mobile device.
Guidelines:
- After each action, if observation tools such as "screenshot" or "accessibility snapshot" are available, call them first to verify the state before deciding the next step.
- Prefer accessibility (a11y) tools to locate elements; fall back to coordinate tapping only if a11y is unavailable.
- For any web search, you MUST use Bing. Do NOT use Google. Prefer typing the query into the browser's address bar so that the default search engine (Bing) is used.
- If you choose to open a URL directly, it must be a Bing URL (e.g., https://cn.bing.com/search?q=...).
- Prefer the sequence: launch browser → focus the address bar → type the query → press enter.
"""
# USER_TASK = "Open the browser, navigate to Baidu, then use Baidu to search for 'Shanghai weather'."


USER_TASK = "Search for content related to 'RAG-Thief'"


def build_openai_client() -> OpenAI:
    api_key = os.environ.get("OPENAI_API_KEY")
    base_url = os.environ.get("OPENAI_BASE_URL", "https://api.siliconflow.cn/v1")
    return OpenAI(api_key=api_key, base_url=base_url)


def mcp_tools_to_openai_tools_and_schema(mcp_tools):
    """把 MCP 工具转换为 OpenAI 函数调用格式，并保留每个工具的 schema 以便参数校正。"""
    tools, schema_map = [], {}
    for t in mcp_tools:
        name = t.name
        desc = t.description or ""
        params = t.inputSchema or {"type": "object", "properties": {}}
        tools.append({
            "type": "function",
            "function": {"name": name, "description": desc, "parameters": params}
        })
        schema_map[name] = params
    return tools, schema_map


def parse_tool_args(raw) -> Dict[str, Any]:
    """
    将模型返回的 tool arguments 解析成 dict：
    - 已是 dict：直接返回
    - 是字符串：反复 json.loads（最多两次），直到得到 dict
    - 其它/空：{}
    """
    if isinstance(raw, dict):
        return raw
    if raw is None:
        return {}
    val = raw
    for _ in range(2):  # 破诸如 '"{}"'、'"{\"url\":\"...\"}"'
        if isinstance(val, str):
            try:
                val2 = json.loads(val)
            except Exception:
                break
            val = val2
        else:
            break
    if isinstance(val, str) and val.strip() == "{}":
        return {}
    return val if isinstance(val, dict) else {}


def normalize_args_by_schema(tool_name: str, args: Dict[str, Any], schema: Dict[str, Any]) -> Dict[str, Any]:
    """若 schema.required 含 'noParams'，自动补 {"noParams":{}}。"""
    if not isinstance(args, dict):
        args = {}
    try:
        required = schema.get("required", [])
        if "noParams" in required and "noParams" not in args:
            args["noParams"] = {}
    except Exception:
        pass
    return args


def content_items_to_text(items) -> str:
    """兼容 dict / Pydantic v2 模型 / 一般对象，把 MCP 返回内容尽量转成可读文本。"""
    parts = []
    for item in items or []:
        obj = item
        # Pydantic v2 BaseModel
        if hasattr(item, "model_dump") and callable(item.model_dump):
            try:
                obj = item.model_dump()
            except Exception:
                obj = item
        if isinstance(obj, dict):
            t = obj.get("type") or obj.get("kind")
            if t == "text":
                parts.append(obj.get("text", ""))
            else:
                parts.append(json.dumps(obj, ensure_ascii=False))
            continue
        if hasattr(obj, "__dict__"):
            d = getattr(obj, "__dict__")
            if isinstance(d, dict):
                t = d.get("type") or d.get("kind")
                if t == "text":
                    parts.append(d.get("text", ""))
                else:
                    parts.append(json.dumps(d, ensure_ascii=False))
                continue
        parts.append(str(obj))
    return "\n".join(p for p in parts if str(p).strip())

async def main():
    load_dotenv()

    # 1) 连接 MCP（SSE）
    # mcp_url = os.environ.get("MCP_SERVER_URL")
    mcp_url = "http://localhost:10000/mcp"
    exit_stack = AsyncExitStack()
    read, write = await exit_stack.enter_async_context(sse_client(url=mcp_url))
    session = await exit_stack.enter_async_context(ClientSession(read, write))
    await session.initialize()

    # 2) 工具发现
    tools_resp = await session.list_tools()
    openai_tools, schema_map = mcp_tools_to_openai_tools_and_schema(tools_resp.tools)
    print("[info] tools:", [t["function"]["name"] for t in openai_tools])

    # （可选）先选默认设备，避免首轮模型忘记调用
    try:
        if "mobile_use_default_device" in schema_map:
            pre = await session.call_tool("mobile_use_default_device", {"noParams": {}})
            print("[info] preselect default device:", content_items_to_text(pre.content))
    except Exception as e:
        print("[warn] preselect default device failed:", e)

    # 3) LLM 客户端
    client = build_openai_client()
    model_name = os.environ.get("OPENAI_MODEL", "Qwen/Qwen2.5-7B-Instruct")

    # 4) 对话初始化
    messages: List[Dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": USER_TASK},
    ]

    # 5) ReAct 循环
    for step in range(12):
        resp = client.chat.completions.create(
            model=model_name,
            messages=messages,
            tools=openai_tools,
            tool_choice="auto",
            temperature=0.2,
        )
        choice = resp.choices[0]
        ai_msg = choice.message

        # 记录 assistant 回复（含 tool_calls）
        tool_calls_payload = []
        if ai_msg.tool_calls:
            for tc in ai_msg.tool_calls:
                tool_calls_payload.append({
                    "id": tc.id,
                    "type": "function",
                    "function": {"name": tc.function.name, "arguments": tc.function.arguments}
                })
        messages.append({
            "role": "assistant",
            "content": ai_msg.content or "",
            **({"tool_calls": tool_calls_payload} if tool_calls_payload else {})
        })

        if not ai_msg.tool_calls:
            print(ai_msg.content or "")
            break

        # 执行工具
        for tc in ai_msg.tool_calls:
            fn_name = tc.function.name
            raw_args = tc.function.arguments
            parsed_args = parse_tool_args(raw_args)
            normalized_args = normalize_args_by_schema(fn_name, parsed_args, schema_map.get(fn_name, {}))

            print(f"[debug] tool={fn_name} raw_args={raw_args!r} -> parsed={parsed_args} -> normalized={normalized_args}")

            try:
                result = await session.call_tool(fn_name, normalized_args)
                result_text = content_items_to_text(result.content) or "(empty)"
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": fn_name,
                    "content": result_text
                })
                print(f"[called tool] {fn_name} => {result_text[:200]}")
            except Exception as e:
                err_msg = f"Tool {fn_name} error: {e}"
                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": fn_name,
                    "content": err_msg
                })
                print(err_msg)

    await exit_stack.aclose()


if __name__ == "__main__":
    asyncio.run(main())
