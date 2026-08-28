"""FastAPI auth router — email/password + Google OAuth.

Endpoints:
    POST /auth/signup        — Create account, return JWT
    POST /auth/login         — Login, return JWT
    GET  /auth/google        — Redirect to Google consent screen
    GET  /auth/google/callback — OAuth callback, issue JWT, redirect to frontend
"""

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
import httpx, os, urllib.parse

from app.db.session import SessionLocal
from app.db.models import User
from app.core.security import verify_password, get_password_hash, create_access_token

auth_router = APIRouter(prefix="/auth", tags=["auth"])


# ── Schemas ──────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str


# ── DB dep ────────────────────────────────────────────────────────────────────

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Email / Password ──────────────────────────────────────────────────────────

@auth_router.post("/signup", response_model=Token, status_code=status.HTTP_201_CREATED)
def signup(user_data: UserCreate, db: Session = Depends(get_db)):
    """Create a new user and return a JWT."""
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(
        email=user_data.email,
        hashed_password=get_password_hash(user_data.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"access_token": create_access_token({"sub": new_user.email}), "token_type": "bearer"}


@auth_router.post("/login", response_model=Token)
def login(user_data: UserLogin, db: Session = Depends(get_db)):
    """Authenticate and return a JWT."""
    user = db.query(User).filter(User.email == user_data.email).first()
    if not user or not verify_password(user_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return {"access_token": create_access_token({"sub": user.email}), "token_type": "bearer"}


# ── Google OAuth ──────────────────────────────────────────────────────────────

GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v3/userinfo"

def _google_cfg():
    # Re-read from env on every call so changes to .env take effect
    # without restarting the server (dotenv overrides at process start)
    from dotenv import load_dotenv
    load_dotenv(override=True)
    client_id = os.getenv("GOOGLE_CLIENT_ID", "").strip().strip('"')
    client_secret = os.getenv("GOOGLE_CLIENT_SECRET", "").strip().strip('"')
    redirect_uri = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/api/v1/auth/google/callback").strip().strip('"')
    frontend_url = os.getenv("FRONTEND_URL", "http://localhost:3000").strip().strip('"')
    return client_id, client_secret, redirect_uri, frontend_url


@auth_router.get("/google")
def google_login():
    """Redirect browser to Google's consent screen."""
    client_id, _, redirect_uri, _ = _google_cfg()
    placeholders = {"", "your-google-client-id-here", "your-google-client-id"}
    if client_id in placeholders:
        raise HTTPException(
            status_code=501,
            detail="Google OAuth is not configured. Add GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET to .env and restart the server."
        )
    params = urllib.parse.urlencode({
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
    })
    return RedirectResponse(f"{GOOGLE_AUTH_URL}?{params}")


@auth_router.get("/google/callback")
async def google_callback(code: str, db: Session = Depends(get_db)):
    """Exchange code for tokens, upsert user, return JWT via redirect."""
    client_id, client_secret, redirect_uri, frontend_url = _google_cfg()

    # 1. Exchange code for access token
    async with httpx.AsyncClient() as client:
        token_res = await client.post(GOOGLE_TOKEN_URL, data={
            "code": code,
            "client_id": client_id,
            "client_secret": client_secret,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        })
        if token_res.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to exchange Google code")
        token_data = token_res.json()
        access_token_google = token_data.get("access_token")

        # 2. Fetch user info
        info_res = await client.get(
            GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token_google}"}
        )
        if info_res.status_code != 200:
            raise HTTPException(status_code=400, detail="Failed to fetch Google user info")
        info = info_res.json()

    email = info.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Google did not return an email address")

    # 3. Upsert user — OAuth users get a sentinel, no real password
    user = db.query(User).filter(User.email == email).first()
    if not user:
        user = User(email=email, hashed_password="OAUTH_NO_PASSWORD")
        db.add(user)
        db.commit()
        db.refresh(user)

    # 4. Issue JWT and redirect back to frontend with token in URL fragment
    jwt = create_access_token({"sub": user.email})
    redirect_target = f"{frontend_url}/auth/callback?token={jwt}&email={urllib.parse.quote(email)}"
    return RedirectResponse(redirect_target)
