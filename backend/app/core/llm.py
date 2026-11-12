"""LLM client factory — returns a LangChain chat model based on config.

Supported providers:
  - "openai"    — OpenAI API (api.openai.com)
  - "anthropic" — Anthropic API (api.anthropic.com)
  - "nvidia"    — NVIDIA NIM API (integrate.api.nvidia.com) — OpenAI-compatible, free tier available
  - "openrouter"— OpenRouter API (openrouter.ai) — OpenAI-compatible, many free models
  - "ollama"    — Local Ollama instance (localhost:11434) — completely private, no data sent externally

The configured provider is the *primary*. When ``LLM_FALLBACK_ENABLED`` is set
(the default), a second model — Kimi K3 on NVIDIA NIM by default — is attached via
LangChain's ``.with_fallbacks()``, so any ``await llm.ainvoke(...)`` that fails
(rate limit, timeout, 5xx, auth error) transparently retries on the fallback.
Call sites are unchanged: the wrapper still exposes ``.ainvoke`` and returns a
message with ``.content``.

Structured-output callers must pass their schema to ``get_llm(structured_output=...)``
rather than calling ``.with_structured_output()`` on the result — the schema has
to be bound to each model *before* they are combined, because the combined
``RunnableWithFallbacks`` has no ``.with_structured_output`` of its own.
"""

from typing import Optional

from langchain_openai import ChatOpenAI
from app.core.config import settings


def _provider_api_key(provider: str) -> Optional[str]:
    """The configured API key for a provider — used to tell if a fallback is usable."""
    return {
        "nvidia": settings.NVIDIA_API_KEY,
        "openrouter": settings.OPENROUTER_API_KEY,
        "anthropic": settings.ANTHROPIC_API_KEY,
        "openai": settings.OPENAI_API_KEY,
    }.get(provider)


def _build_chat_model(provider: str, model: str):
    """Construct a LangChain chat model for one provider + model name.

    NVIDIA NIM, OpenRouter, and Ollama are OpenAI-compatible, so they reuse
    ChatOpenAI with a custom base_url. temperature=0 everywhere — security
    triage wants deterministic output, not creativity.
    """
    if provider == "ollama":
        return ChatOpenAI(
            model=model,
            api_key="ollama",  # Ollama doesn't need a real key but ChatOpenAI requires one
            base_url=f"{settings.OLLAMA_BASE_URL}/v1",
            temperature=0,
        )

    if provider == "nvidia":
        return ChatOpenAI(
            model=model,
            api_key=settings.NVIDIA_API_KEY,
            base_url="https://integrate.api.nvidia.com/v1",
            temperature=0,
        )

    if provider == "openrouter":
        return ChatOpenAI(
            model=model,
            api_key=settings.OPENROUTER_API_KEY,
            base_url="https://openrouter.ai/api/v1",
            temperature=0,
        )

    if provider == "anthropic":
        # Imported lazily so the OpenAI-compat providers don't pay for it.
        from langchain_anthropic import ChatAnthropic
        return ChatAnthropic(
            model=model,
            api_key=settings.ANTHROPIC_API_KEY,
            temperature=0,
        )

    # Default — OpenAI
    return ChatOpenAI(
        model=model,
        api_key=settings.OPENAI_API_KEY,
        temperature=0,
    )


def _build_fallback_model():
    """The configured fallback chat model, or None when no usable fallback applies.

    Skipped if disabled, if it's identical to the primary, or if the fallback
    provider has no API key (an unusable fallback would only fail again on top
    of the primary failure).
    """
    if not settings.LLM_FALLBACK_ENABLED:
        return None

    provider = settings.LLM_FALLBACK_PROVIDER
    model = settings.LLM_FALLBACK_MODEL
    is_same = provider == settings.LLM_PROVIDER and model == settings.LLM_MODEL
    if is_same or not _provider_api_key(provider):
        return None

    return _build_chat_model(provider, model)


def get_llm(structured_output=None):
    """Return the configured primary LLM, with a fallback attached when available.

    Uses ``settings.LLM_PROVIDER`` / ``LLM_MODEL`` for the primary. When a
    fallback is configured and usable, the result is
    ``primary.with_fallbacks([fallback])`` — same ``.ainvoke()`` interface,
    automatic failover on error.

    Pass ``structured_output=<pydantic model>`` to bind a structured-output
    schema; it is applied to both the primary and the fallback before they are
    combined, so ``.ainvoke()`` returns the parsed object on either path.
    """
    primary = _build_chat_model(settings.LLM_PROVIDER, settings.LLM_MODEL)
    fallback = _build_fallback_model()

    def _prepare(model):
        return model.with_structured_output(structured_output) if structured_output is not None else model

    if fallback is None:
        return _prepare(primary)

    return _prepare(primary).with_fallbacks([_prepare(fallback)])


def get_llm_for_user(user_prefs: dict | None = None, structured_output=None):
    """Return an LLM respecting the user's local-AI preference.

    If ``user_prefs`` is provided and ``use_local_ai`` is True, build an Ollama
    model pointing at the user's configured URL / model. Otherwise fall back to
    the normal cloud ``get_llm()`` path.

    This keeps the existing ``get_llm()`` completely unchanged — call sites that
    don't care about per-user overrides continue to work as before.
    """
    if user_prefs and user_prefs.get("use_local_ai"):
        base_url = user_prefs.get("ollama_base_url", "http://localhost:11434")
        model_name = user_prefs.get("ollama_model", "llama3.1:8b")
        primary = ChatOpenAI(
            model=model_name,
            api_key="ollama",
            base_url=f"{base_url}/v1",
            temperature=0,
        )
        if structured_output is not None:
            return primary.with_structured_output(structured_output)
        return primary

    return get_llm(structured_output=structured_output)
