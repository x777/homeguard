"""LLM configuration management."""

import os
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Optional

import yaml

from .constants import DEFAULT_BACKEND_URL

CONFIG_DIR = Path.home() / ".homeguard"
CONFIG_PATH = CONFIG_DIR / "config.yaml"


@dataclass
class LLMConfig:
    provider: str = "backend"
    model: str = "auto"
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    scan_mode: str = "quick"  # "quick" or "full"

    @property
    def is_backend_proxy(self) -> bool:
        return self.provider == "backend"

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


# Provider presets
PROVIDERS = {
    "openai": {"model": "gpt-4", "base_url": None},
    "anthropic": {"model": "claude-3-sonnet-20240229", "base_url": None},
    "deepseek": {"model": "deepseek-chat", "base_url": "https://api.deepseek.com/v1"},
    "ollama": {"model": "llama3", "base_url": "http://localhost:11434"},
    "bedrock": {"model": "anthropic.claude-3-sonnet-20240229-v1:0", "base_url": None},
}


def load_config() -> LLMConfig:
    """Load config from file or return default (backend proxy)."""
    if CONFIG_PATH.exists():
        with open(CONFIG_PATH) as f:
            data = yaml.safe_load(f) or {}
            llm_data = data.get("llm", {})
            provider = llm_data.get("provider", "backend")

            api_key = llm_data.get("api_key")
            if not api_key and provider != "backend":
                api_key = os.getenv(f"{provider.upper()}_API_KEY")

            return LLMConfig(
                provider=provider,
                model=llm_data.get("model", "auto"),
                api_key=api_key,
                base_url=llm_data.get("base_url"),
                scan_mode=llm_data.get("scan_mode", "quick"),
            )

    return LLMConfig(provider="backend", model="auto", base_url=DEFAULT_BACKEND_URL)


def save_config(config: LLMConfig) -> bool:
    """Save config to file. Returns True on success."""
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        data = {"llm": config.to_dict()}
        with open(CONFIG_PATH, "w") as f:
            yaml.dump(data, f, default_flow_style=False)
        return True
    except PermissionError:
        print(f"⚠️  Permission denied writing to {CONFIG_PATH}")
        print(f"   Try: sudo chown -R $USER {CONFIG_DIR}")
        return False
    except Exception as e:
        print(f"⚠️  Error saving config: {e}")
        return False


def setup_wizard() -> Optional[LLMConfig]:
    """Interactive setup for LLM configuration."""
    import questionary

    provider = questionary.select(
        "Select LLM provider:",
        choices=[
            questionary.Choice("OpenAI (GPT-4)", value="openai"),
            questionary.Choice("Anthropic (Claude)", value="anthropic"),
            questionary.Choice("DeepSeek", value="deepseek"),
            questionary.Choice("Ollama (Local - Free)", value="ollama"),
            questionary.Choice("AWS Bedrock", value="bedrock"),
            questionary.Choice("Skip for now", value=None),
        ],
    ).ask()

    if not provider:
        return None

    preset = PROVIDERS[provider]

    if provider == "ollama":
        # Ollama doesn't need API key
        base_url = questionary.text(
            "Ollama URL:", default="http://localhost:11434"
        ).ask()
        model = questionary.text("Model name:", default="llama3").ask()
        config = LLMConfig(provider=provider, model=model, base_url=base_url)
    else:
        api_key = questionary.password(f"Enter {provider.upper()} API key:").ask()
        if not api_key:
            return None
        model = questionary.text("Model:", default=preset["model"]).ask()
        config = LLMConfig(
            provider=provider, model=model, api_key=api_key, base_url=preset["base_url"]
        )

    if save_config(config):
        return config
    return None
