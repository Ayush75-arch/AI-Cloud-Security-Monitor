"""
CloudGuard-AI — Auth Router
POST /auth/login  → returns JWT (rate limited: 10/minute per IP)
GET  /auth/me     → current user info (requires valid token)

Security:
- Rate limited via slowapi (10 attempts/minute per IP)
- Bcrypt password verification (constant-time)
- JWT with expiry (configurable via ACCESS_TOKEN_EXPIRE_MINUTES)
- Generic error messages (no user enumeration)
- Full audit logging on success/failure/block
"""
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from app.auth import (
    LoginRequest,
    TokenData,
    TokenResponse,
    UserOut,
    authenticate_user,
    create_access_token,
    get_current_user,
    DEMO_USERS,
)
from app.config import settings
from app.schemas import APIResponse
from app.utils.audit_log import log_login_failure, log_login_success
from app.utils.rate_limit import limiter

router = APIRouter(prefix="/auth", tags=["Auth"])


@router.post("/login")
@limiter.limit("10/minute")   # Rule 6: brute-force protection on login
async def login(request: Request, body: LoginRequest) -> APIResponse:
    """
    Authenticate and return JWT.

    Rate limited: 10 attempts per minute per IP.
    Returns identical error for wrong username OR wrong password
    to prevent user enumeration attacks.
    """
    client_ip = request.client.host if request.client else "unknown"

    user = authenticate_user(body.username, body.password)

    if not user:
        # Rule 14: audit log every failed login
        log_login_failure(username=body.username, ip=client_ip)
        # Rule 5: generic error — never reveal whether username exists
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",   # same message for bad user OR bad password
        )

    # Rule 14: audit log successful logins
    log_login_success(username=user["username"], ip=client_ip)

    token = create_access_token({"sub": user["username"], "role": user["role"]})
    return APIResponse(data=TokenResponse(
        access_token=token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    ))


@router.get("/me")
async def get_me(
    current_user: Annotated[TokenData, Depends(get_current_user)]
) -> APIResponse:
    user = DEMO_USERS.get(current_user.username, {})
    return APIResponse(data=UserOut(
        username=current_user.username,
        role=current_user.role,
        email=user.get("email", ""),
    ))
