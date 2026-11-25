from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.core.config import settings

# ── Database URL resolution ───────────────────────────────────────────────
# Priority:
#  1. DB_URL env var (explicit full connection string)
#  2. POSTGRES_* env vars assembled into a postgresql:// URL
#  3. SQLite fallback — zero-config, works offline and locally
#
# The SQLite fallback kicks in automatically when the Neon / Postgres host
# cannot be reached (e.g. Neon free-tier auto-pause, no network, local dev).

_SQLITE_FALLBACK = "sqlite:///./securai.db"

db_url = settings.DB_URL
if not db_url:
    # Only build postgres URL if server is not the default placeholder
    if settings.POSTGRES_SERVER not in ("localhost", ""):
        db_url = (
            f"postgresql://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}"
            f"@{settings.POSTGRES_SERVER}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"
        )
    else:
        db_url = _SQLITE_FALLBACK

# If pointing to a remote postgres host, verify DNS before connecting.
# If host is unreachable, fall back to SQLite so the app starts locally.
_is_sqlite = db_url.startswith("sqlite")

if not _is_sqlite:
    import socket
    import sys
    from urllib.parse import urlparse
    try:
        _parsed = urlparse(db_url)
        _host = _parsed.hostname or "localhost"
        _port = _parsed.port or 5432
        socket.setdefaulttimeout(4)
        socket.getaddrinfo(_host, _port)
    except Exception as _dns_err:
        print(
            f"[session] WARNING: Cannot reach DB host '{_host}' "
            f"({type(_dns_err).__name__}: {_dns_err}). "
            f"Falling back to SQLite at {_SQLITE_FALLBACK}",
            file=sys.stderr,
        )
        db_url = _SQLITE_FALLBACK
        _is_sqlite = True

# Build engine with driver-appropriate options
if _is_sqlite:
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False},
    )
else:
    engine = create_engine(
        db_url,
        pool_pre_ping=True,
        pool_recycle=300,
        pool_size=5,
        max_overflow=10,
        connect_args={
            "keepalives": 1,
            "keepalives_idle": 30,
            "keepalives_interval": 10,
            "keepalives_count": 5,
        },
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
