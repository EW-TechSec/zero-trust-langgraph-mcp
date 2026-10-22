"""LLM provider selection, driven entirely by environment variables."""

from __future__ import annotations

import os

from langchain_core.language_models.chat_models import BaseChatModel


def get_llm() -> BaseChatModel:
    provider = os.getenv("LLM_PROVIDER", "anthropic").lower()

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic

        model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-5")
        return ChatAnthropic(model=model)

    if provider == "ollama":
        from langchain_ollama import ChatOllama

        model = os.getenv("OLLAMA_MODEL", "llama3.1")
        base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        return ChatOllama(model=model, base_url=base_url)

    raise ValueError(
        f"Unsupported LLM_PROVIDER '{provider}'. Implemented providers: 'anthropic', 'ollama'. "
        "Add a new branch here to support another provider."
    )
