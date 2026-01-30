"""LLM provider abstraction using litellm or backend proxy."""

import json
import httpx
from typing import Optional
from .config import LLMConfig
from .constants import DEFAULT_BACKEND_URL, LLM_TIMEOUT_SECONDS
from .prompts import AGENT_SYSTEM_PROMPT

# For backward compatibility
SYSTEM_PROMPT = AGENT_SYSTEM_PROMPT


async def chat_with_backend(messages: list[dict], tools: list[dict], base_url: str) -> dict:
    """Send chat request to HomeGuard backend."""
    async with httpx.AsyncClient(timeout=LLM_TIMEOUT_SECONDS) as client:
        response = await client.post(
            f"{base_url}/api/chat",
            json={"messages": messages, "tools": tools},
        )
        response.raise_for_status()
        data = response.json()

        # Convert backend response to litellm-like format
        class FakeChoice:
            def __init__(self, msg_data, finish):
                self.message = FakeMessage(msg_data)
                self.finish_reason = finish

        class FakeMessage:
            def __init__(self, data):
                self.content = data.get("content")
                self.role = data.get("role")
                self.tool_calls = None
                if data.get("tool_calls"):
                    self.tool_calls = [FakeToolCall(tc) for tc in data["tool_calls"]]

        class FakeToolCall:
            def __init__(self, data):
                self.id = data["id"]
                self.type = data["type"]
                self.function = FakeFunction(data["function"])

        class FakeFunction:
            def __init__(self, data):
                self.name = data["name"]
                self.arguments = data["arguments"]

        class FakeResponse:
            def __init__(self, data):
                self.choices = [FakeChoice(data["message"], data["finish_reason"])]

        return FakeResponse(data)


def chat_with_tools(
    messages: list[dict],
    config: LLMConfig,
) -> dict:
    """Send messages to LLM and get response with potential tool calls."""
    from .tools import TOOL_DEFINITIONS

    # Use backend proxy
    if config.is_backend_proxy:
        import asyncio
        base_url = config.base_url or DEFAULT_BACKEND_URL
        try:
            return asyncio.get_event_loop().run_until_complete(
                chat_with_backend(messages, TOOL_DEFINITIONS, base_url)
            )
        except RuntimeError:
            # No event loop running
            return asyncio.run(chat_with_backend(messages, TOOL_DEFINITIONS, base_url))

    # Direct LLM call
    from litellm import completion

    if config.provider == "ollama":
        model = f"ollama/{config.model}"
    elif config.provider == "deepseek":
        model = f"deepseek/{config.model}"
    elif config.provider == "bedrock":
        model = f"bedrock/{config.model}"
    elif config.provider == "anthropic":
        model = f"anthropic/{config.model}"
    else:
        model = config.model

    try:
        response = completion(
            model=model,
            messages=messages,
            tools=TOOL_DEFINITIONS,
            api_key=config.api_key,
            base_url=config.base_url,
        )
        return response
    except Exception as e:
        raise RuntimeError(f"LLM error: {e}")


def extract_tool_calls(response: dict) -> list[dict]:
    """Extract tool calls from LLM response."""
    message = response.choices[0].message
    if hasattr(message, "tool_calls") and message.tool_calls:
        return [
            {
                "id": tc.id,
                "name": tc.function.name,
                "arguments": json.loads(tc.function.arguments),
            }
            for tc in message.tool_calls
        ]
    return []


def get_response_text(response: dict) -> Optional[str]:
    """Get text content from LLM response."""
    message = response.choices[0].message
    return message.content
