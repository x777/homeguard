"""Chat client for backend LLM integration."""

import httpx
from homeguard.agent.config import load_config
from homeguard.agent.constants import DEFAULT_BACKEND_URL, LLM_TIMEOUT_SECONDS
from homeguard.agent.prompts import get_chat_system_prompt


class ChatClient:
    """Client for HomeGuard backend chat API."""
    
    def __init__(self):
        self.config = load_config()
        self.base_url = self.config.base_url or DEFAULT_BACKEND_URL
        self.conversation_history: list[dict] = []
    
    async def send_message(self, user_message: str, context: str = "") -> str:
        """Send a message to the LLM and get response."""
        # Add context to first message if provided
        if context and not self.conversation_history:
            system_prompt = get_chat_system_prompt(context)
            self.conversation_history.append({
                "role": "system",
                "content": system_prompt
            })
        
        # Add user message
        self.conversation_history.append({
            "role": "user",
            "content": user_message
        })
        
        try:
            async with httpx.AsyncClient(timeout=LLM_TIMEOUT_SECONDS) as client:
                response = await client.post(
                    f"{self.base_url}/api/chat",
                    json={
                        "messages": self.conversation_history,
                        "model": self.config.model if self.config.model != "auto" else "deepseek-chat"
                    }
                )
                response.raise_for_status()
                data = response.json()
                
                # Extract assistant response
                assistant_message = data["message"]["content"]
                
                # Add to history
                self.conversation_history.append({
                    "role": "assistant",
                    "content": assistant_message
                })
                
                return assistant_message
                
        except httpx.ConnectError:
            # Don't add error to history - remove user message
            self.conversation_history.pop()
            return f"❌ Cannot connect to backend at {self.base_url}. Make sure the API server is running."
        except httpx.HTTPError as e:
            # Don't add error to history - remove user message
            self.conversation_history.pop()
            return f"❌ Backend error: {str(e)}"
        except Exception as e:
            # Don't add error to history - remove user message
            self.conversation_history.pop()
            return f"❌ Error: {str(e)}"
    
    def reset_conversation(self):
        """Clear conversation history."""
        self.conversation_history = []
