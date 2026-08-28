from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    PROJECT_NAME: str = "AuthTrack"
    API_V1_STR: str = "/api/v1"

    # LLM Settings
    # Provider choices: "openai" | "anthropic" | "nvidia" | "openrouter"
    LLM_PROVIDER: str = "openrouter"
    LLM_MODEL: str = "nvidia/nemotron-3-ultra-550b-a55b:free"  # best free model on OpenRouter

    # API Keys — only the one matching LLM_PROVIDER is required
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    NVIDIA_API_KEY: Optional[str] = None       # from https://build.nvidia.com
    OPENROUTER_API_KEY: Optional[str] = None   # from https://openrouter.ai/keys

    # Database Settings
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "postgres"
    POSTGRES_DB: str = "authtrack"
    POSTGRES_PORT: str = "5432"

    # Vector Database Settings
    CHROMADB_HOST: str = "localhost"
    CHROMADB_PORT: int = 8000

    # Upstash Settings
    UPSTASH_SEARCH_REST_URL: Optional[str] = None
    UPSTASH_SEARCH_REST_TOKEN: Optional[str] = None

    # Full DB connection string
    DB_URL: Optional[str] = None

    # Google OAuth Settings (optional)
    GOOGLE_CLIENT_ID: Optional[str] = None
    GOOGLE_CLIENT_SECRET: Optional[str] = None
    GOOGLE_REDIRECT_URI: Optional[str] = None
    FRONTEND_URL: Optional[str] = None
    SECRET_KEY: Optional[str] = None

    class Config:
        case_sensitive = True
        env_file = ".env"


settings = Settings()
