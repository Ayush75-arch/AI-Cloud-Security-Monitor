"""
CloudGuard-AI — JWT Authentication
Bearer token auth for production API endpoints.
Supports: login, token creation, current user dependency.

In production: connect to your IdP (Okta, Auth0, AWS Cognito).
For demo: simple in-memory user store with bcrypt passwords.
"""
from datetime import datetime, timedelta, timezone
from typing import Annotated

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ── Password hashing ──────────────────────────────────────────────────────────


def _hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12)).decode()


def _verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


# ── Demo user store (replace with DB in production) ──────────────────────────
# Passwords are bcrypt hashed. Default: admin/cloudguard123

DEMO_USERS: dict[str, dict] = {
    "admin": {
        "username": "admin",
        "hashed_password": "$2b$12$kXuRZIbj98QkLYjqHajWzOLkjhGquI/xLg6W6wTwWb.9P8y.tfEnm",
        "role": "admin",
        "email": "admin@cloudguard.local",
    },
    "analyst": {
        "username": "analyst",
        "hashed_password": "$2b$12$hDMRpyBKPRtaIeUBP6mLx.sGNrB3dXlSo.ItsgYOK.E52J37/XT76",
        "role": "analyst",
        "email": "analyst@cloudguard.local",
    },
}

# ── Schemas ───────────────────────────────────────────────────────────────────

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class TokenData(BaseModel):
    username: str
    role: str


class LoginRequest(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    username: str
    role: str
    email: str


# ── Token creation ────────────────────────────────────────────────────────────

def create_access_token(data: dict) -> str:
    payload = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    payload.update({"exp": expire, "iat": datetime.now(timezone.utc)})
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def verify_token(token: str) -> TokenData:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        username: str = payload.get("sub", "")
        role: str = payload.get("role", "analyst")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        return TokenData(username=username, role=role)
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc


# ── FastAPI dependencies ──────────────────────────────────────────────────────

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)],
) -> TokenData:
    """Dependency: validates Bearer token, returns TokenData."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return verify_token(credentials.credentials)


async def require_admin(current_user: Annotated[TokenData, Depends(get_current_user)]) -> TokenData:
    """Dependency: requires admin role."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


# ── Login endpoint helper ─────────────────────────────────────────────────────

def authenticate_user(username: str, password: str) -> dict | None:
    user = DEMO_USERS.get(username)
    if not user:
        return None
    if not _verify_password(password, user["hashed_password"]):
        return None
    return user
