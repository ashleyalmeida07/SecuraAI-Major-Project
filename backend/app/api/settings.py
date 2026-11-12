"""Settings API — allows the frontend to toggle between cloud and local AI."""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.api.deps import get_current_user

settings_router = APIRouter(prefix="/settings", tags=["settings"])


class LLMSettingsRequest(BaseModel):
    use_local_ai: bool = False
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"


# In-memory per-user store (keyed by user email).
# In production this would go to the DB, but for the demo it works fine.
_user_llm_prefs: dict[str, dict] = {}


def get_user_llm_prefs(email: str) -> dict:
    """Read a user's LLM preferences — used by scan endpoints."""
    return _user_llm_prefs.get(email, {
        "use_local_ai": False,
        "ollama_base_url": "http://localhost:11434",
        "ollama_model": "llama3.1:8b",
    })


@settings_router.post("/llm")
async def update_llm_settings(
    body: LLMSettingsRequest,
    user=Depends(get_current_user),
):
    """Save the user's LLM preference (cloud vs local Ollama)."""
    email = getattr(user, "email", "anonymous")
    _user_llm_prefs[email] = body.model_dump()
    return {"status": "ok", "settings": _user_llm_prefs[email]}


@settings_router.get("/llm")
async def get_llm_settings(user=Depends(get_current_user)):
    """Return the user's current LLM preference."""
    email = getattr(user, "email", "anonymous")
    prefs = get_user_llm_prefs(email)
    return {"status": "ok", "settings": prefs}
