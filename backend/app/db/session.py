from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from app.core.config import settings
import os

# We will use the DB_URL from environment directly if available, otherwise construct from components
db_url = settings.DB_URL
if not db_url:
    db_url = f"postgresql://{settings.POSTGRES_USER}:{settings.POSTGRES_PASSWORD}@{settings.POSTGRES_SERVER}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"

engine = create_engine(
    db_url,
    # ── Neon cold-start / auto-suspend fix ──────────────────────────────────
    # pool_pre_ping tests each connection before handing it out; stale ones
    # (dropped by Neon's scale-to-zero) are discarded and a fresh connection
    # is opened transparently.
    pool_pre_ping=True,
    # Recycle connections after 5 min (Neon suspends at the same interval,
    # so any connection older than this is already dead).
    pool_recycle=300,
    pool_size=5,
    max_overflow=10,
    # SSL keepalives — tells the TCP stack to probe the Neon proxy while
    # the connection is idle so the OS drops it before psycopg2 tries to
    # reuse it (avoids the "SSL connection closed unexpectedly" error).
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
