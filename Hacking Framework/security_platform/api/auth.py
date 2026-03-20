"""
Authentication helpers — JWT token generation / validation and
FastAPI dependency for extracting the current authenticated user.

SECURITY NOTES:
  - Tokens are signed with HS256 using the platform SECRET_KEY.
  - Passwords are stored as bcrypt hashes (never in plaintext).
  - API keys are stored as SHA-256 hashes (never in plaintext).
  - Token expiry is enforced server-side on every request.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, OAuth2PasswordBearer
import bcrypt as _bcrypt
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config.settings import security_settings
from database.database import get_db
from database.models import User

logger = logging.getLogger(__name__)


# ─── OAuth2 bearer scheme ─────────────────────────────────────────────────────

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")
bearer_scheme = HTTPBearer(auto_error=False)


# ─── Password utilities ───────────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    """Return a bcrypt hash of *plain* password."""
    return _bcrypt.hashpw(plain.encode("utf-8"), _bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Return True if *plain* matches the stored *hashed* password."""
    try:
        return _bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


# ─── API key utilities ────────────────────────────────────────────────────────

def generate_api_key() -> str:
    """Generate a new cryptographically random API key."""
    return secrets.token_urlsafe(32)


def hash_api_key(key: str) -> str:
    """Return the SHA-256 hex digest for storage."""
    return hashlib.sha256(key.encode()).hexdigest()


# ─── JWT utilities ────────────────────────────────────────────────────────────

class TokenData(BaseModel):
    user_id: str
    username: str


def create_access_token(user_id: str, username: str) -> str:
    """
    Create a signed JWT access token.

    Args:
        user_id:  Subject (user database ID).
        username: Username claim for readability.

    Returns:
        Encoded JWT string.
    """
    expire = datetime.now(timezone.utc) + timedelta(
        minutes=security_settings.access_token_expire_minutes
    )
    payload = {
        "sub": user_id,
        "username": username,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(
        payload,
        security_settings.secret_key,
        algorithm=security_settings.algorithm,
    )


def decode_access_token(token: str) -> TokenData:
    """
    Decode and validate a JWT token.

    Raises:
        HTTPException 401 if the token is invalid or expired.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token,
            security_settings.secret_key,
            algorithms=[security_settings.algorithm],
        )
        user_id: Optional[str] = payload.get("sub")
        username: Optional[str] = payload.get("username")
        if not user_id or not username:
            raise credentials_exception
        return TokenData(user_id=user_id, username=username)
    except JWTError:
        raise credentials_exception


# ─── FastAPI dependencies ─────────────────────────────────────────────────────

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    FastAPI dependency: resolve the Bearer token or API key to a User.

    Accepts:
      - Authorization: Bearer <jwt>
      - Authorization: Bearer <api_key>
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated.",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not credentials:
        raise credentials_exception

    token = credentials.credentials

    # ── Try JWT first ──────────────────────────────────────────────────────
    try:
        token_data = decode_access_token(token)
        stmt = select(User).where(User.id == token_data.user_id, User.is_active == True)
        result = await db.execute(stmt)
        user = result.scalar_one_or_none()
        if user:
            return user
    except HTTPException:
        pass  # Not a valid JWT — try API key

    # ── Try API key ────────────────────────────────────────────────────────
    key_hash = hash_api_key(token)
    stmt = select(User).where(User.api_key == key_hash, User.is_active == True)
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    if user:
        return user

    raise credentials_exception


async def require_superuser(current_user: User = Depends(get_current_user)) -> User:
    """
    FastAPI dependency: ensure the authenticated user has superuser privileges.

    Raises 403 Forbidden for regular users.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser privileges required.",
        )
    return current_user
