"""
FastAPI application factory and server entry point.

Architecture:
  - Lifespan context manager handles startup / shutdown hooks
  - CORS is configured from settings
  - All API routers are mounted under /api/v1
  - A dedicated /auth router handles token issuance
  - A /health endpoint is exposed for load-balancer probes
  - WebSocket support is included via routes_scan

Security hardening:
  - TrustedHostMiddleware rejects requests with invalid Host headers
  - CORS allow_origins is read from settings (never wildcard in production)
  - API keys and JWT tokens are validated on every protected route
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import create_access_token, get_current_user, verify_password
from api.routes_reports import router as reports_router
from api.routes_scan import router as scan_router
from api.routes_targets import router as targets_router
from dashboard.backend.dashboard_api import router as dashboard_router
from config.settings import security_settings, settings
from core.engine import get_engine
from database.database import close_database, get_db, init_database
from database.models import User

logger = logging.getLogger(__name__)


# ─── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application startup and shutdown hooks."""
    logger.info("Starting %s v%s", settings.app_name, settings.app_version)

    # Initialise database tables (dev mode — use Alembic in production)
    if settings.environment == "development":
        await init_database()

    # Warm up the security engine (discovers plugins)
    engine = get_engine()
    await engine.startup()

    logger.info("Platform ready. %d modules loaded.", len(engine.plugin_loader))
    yield

    # Shutdown
    await engine.shutdown()
    await close_database()
    logger.info("Platform shut down cleanly.")


# ─── Application factory ──────────────────────────────────────────────────────

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description=(
            "Enterprise-grade security research and automation platform. "
            "**For authorised testing only.**"
        ),
        docs_url="/docs" if settings.debug else None,
        redoc_url="/redoc" if settings.debug else None,
        lifespan=lifespan,
    )

    # ── Middleware ─────────────────────────────────────────────────────────────
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=security_settings.allowed_hosts,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=security_settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type"],
    )

    # ── Routers ────────────────────────────────────────────────────────────────
    prefix = settings.api_prefix

    app.include_router(targets_router, prefix=prefix)
    app.include_router(scan_router,    prefix=prefix)
    app.include_router(reports_router, prefix=prefix)
    app.include_router(dashboard_router, prefix=prefix)

    # Auth router (inline — small enough to not need a separate file)
    _register_auth_routes(app, prefix)

    # Health check
    @app.get("/health", tags=["Health"], include_in_schema=False)
    async def health() -> JSONResponse:
        return JSONResponse({"status": "ok", "version": settings.app_version})

    # Dashboard SPA — serve index.html at root and mount static assets
    _frontend_dir = Path(__file__).parent.parent / "dashboard" / "frontend"
    if _frontend_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(_frontend_dir)), name="static")

        @app.get("/", include_in_schema=False)
        async def dashboard_index() -> FileResponse:
            return FileResponse(str(_frontend_dir / "index.html"))

    return app


# ─── Auth routes (inline) ─────────────────────────────────────────────────────

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class UserResponse(BaseModel):
    id: str
    username: str
    email: str
    is_active: bool
    is_superuser: bool


def _register_auth_routes(app: FastAPI, prefix: str) -> None:
    """Register authentication routes directly on the app (no separate router needed)."""
    from api.auth import hash_password

    @app.post(
        f"{prefix}/auth/token",
        response_model=TokenResponse,
        tags=["Auth"],
        summary="Obtain a JWT access token",
    )
    async def login(
        form: OAuth2PasswordRequestForm = Depends(),
        db: AsyncSession = Depends(get_db),
    ) -> TokenResponse:
        """Exchange username + password for a JWT bearer token."""
        result = await db.execute(
            select(User).where(User.username == form.username, User.is_active == True)
        )
        user: User | None = result.scalar_one_or_none()

        if not user or not verify_password(form.password, user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = create_access_token(user_id=user.id, username=user.username)
        return TokenResponse(access_token=token)

    @app.post(
        f"{prefix}/auth/register",
        response_model=UserResponse,
        status_code=status.HTTP_201_CREATED,
        tags=["Auth"],
        summary="Register a new platform user",
    )
    async def register(
        payload: UserCreate,
        db: AsyncSession = Depends(get_db),
    ) -> UserResponse:
        """Create a new user account.  First registered user becomes superuser."""
        # Check for duplicate username / email
        existing = await db.execute(
            select(User).where(
                (User.username == payload.username) | (User.email == payload.email)
            )
        )
        if existing.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Username or email already registered.",
            )

        # First user becomes superuser
        user_count = await db.execute(select(User))
        is_first = user_count.first() is None

        user = User(
            username=payload.username,
            email=payload.email,
            hashed_password=hash_password(payload.password),
            is_superuser=is_first,
        )
        db.add(user)
        await db.flush()
        await db.refresh(user)

        return UserResponse(
            id=user.id,
            username=user.username,
            email=user.email,
            is_active=user.is_active,
            is_superuser=user.is_superuser,
        )

    @app.get(
        f"{prefix}/auth/me",
        response_model=UserResponse,
        tags=["Auth"],
        summary="Get current user info",
    )
    async def me(current_user: User = Depends(get_current_user)) -> UserResponse:
        return UserResponse(
            id=current_user.id,
            username=current_user.username,
            email=current_user.email,
            is_active=current_user.is_active,
            is_superuser=current_user.is_superuser,
        )


# ─── Module-level app instance (used by uvicorn) ──────────────────────────────

app = create_app()
