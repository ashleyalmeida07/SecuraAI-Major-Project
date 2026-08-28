"""LLM client factory — returns a LangChain chat model based on config.

Supported providers:
  - "openai"    — OpenAI API (api.openai.com)
  - "anthropic" — Anthropic API (api.anthropic.com)
  - "nvidia"    — NVIDIA NIM API (integrate.api.nvidia.com) — OpenAI-compatible, free tier available
  - "openrouter"— OpenRouter API (openrouter.ai) — OpenAI-compatible, many free models
"""

from langchain_openai import ChatOpenAI
from app.core.config import settings


def get_llm():
    """Return the configured LLM chat model.

    Uses settings.LLM_PROVIDER to choose the backend.
    NVIDIA NIM and OpenRouter are both OpenAI-compatible, so they
    reuse ChatOpenAI with a custom base_url and api_key.
    """
    if settings.LLM_PROVIDER == "nvidia":
        return ChatOpenAI(
            model=settings.LLM_MODEL,
            api_key=settings.NVIDIA_API_KEY,
            base_url="https://integrate.api.nvidia.com/v1",
            temperature=0,
        )

    if settings.LLM_PROVIDER == "openrouter":
        return ChatOpenAI(
            model=settings.LLM_MODEL,
            api_key=settings.OPENROUTER_API_KEY,
            base_url="https://openrouter.ai/api/v1",
            temperature=0,
        )

    if settings.LLM_PROVIDER == "anthropic":
        # Keep Anthropic support without importing langchain-anthropic
        # (it is still installed but we route through OpenAI-compat layer here)
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=settings.LLM_MODEL,
            api_key=settings.ANTHROPIC_API_KEY,
            temperature=0,
        )

    # Default — OpenAI
    return ChatOpenAI(
        model=settings.LLM_MODEL,
        api_key=settings.OPENAI_API_KEY,
        temperature=0,
    )
