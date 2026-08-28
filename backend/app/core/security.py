from datetime import datetime, timedelta
from typing import Optional
import bcrypt
import jwt
from app.core.config import settings

SECRET_KEY = getattr(settings, "SECRET_KEY", "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = getattr(settings, "ACCESS_TOKEN_EXPIRE_MINUTES", 30)

# ── use bcrypt directly — passlib is incompatible with bcrypt >= 4.x ──────────

def _encode(password: str) -> bytes:
    """Encode and safely truncate to bcrypt's 72-byte max."""
    return password.encode("utf-8")[:72]

def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Google OAuth users have no real password
    if hashed_password == "OAUTH_NO_PASSWORD":
        return False
    try:
        return bcrypt.checkpw(_encode(plain_password), hashed_password.encode("utf-8"))
    except Exception:
        return False

def get_password_hash(password: str) -> str:
    hashed = bcrypt.hashpw(_encode(password), bcrypt.gensalt())
    return hashed.decode("utf-8")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
