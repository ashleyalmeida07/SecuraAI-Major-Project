from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from sqlalchemy.orm import Session
from app.db.session import SessionLocal
from app.db.models import User
from app.core.security import SECRET_KEY, ALGORITHM

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/auth/login", auto_error=False)

# ID of the primary/first registered user — used by CLI/MCP when no JWT is supplied.
# Change this if your first user's DB id is different.
CLI_DEFAULT_USER_ID = 1

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def _stub_cli_user() -> User:
    """Return a lightweight User object for unauthenticated CLI/MCP requests.
    This never touches the database, so it works even when Neon is slow or
    the connection pool is stale."""
    stub = User.__new__(User)
    stub.id = CLI_DEFAULT_USER_ID
    stub.email = "cli@secura.local"
    stub.is_active = True
    return stub

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    # ── No token → CLI / MCP request ────────────────────────────────────────
    if not token or token == "null" or token == "undefined":
        return _stub_cli_user()

    # ── Token present → validate JWT ────────────────────────────────────────
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception

    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    return user
