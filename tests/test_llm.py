import pytest

from agent.llm import get_llm


def test_defaults_to_anthropic(monkeypatch):
    monkeypatch.delenv("LLM_PROVIDER", raising=False)
    from langchain_anthropic import ChatAnthropic

    assert isinstance(get_llm(), ChatAnthropic)


def test_ollama_provider(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("OLLAMA_MODEL", "llama3.1")
    monkeypatch.setenv("OLLAMA_BASE_URL", "http://localhost:11434")
    from langchain_ollama import ChatOllama

    llm = get_llm()
    assert isinstance(llm, ChatOllama)
    assert llm.model == "llama3.1"
    assert llm.base_url == "http://localhost:11434"


def test_unsupported_provider_raises(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "not-a-real-provider")
    with pytest.raises(ValueError, match="Unsupported LLM_PROVIDER"):
        get_llm()
