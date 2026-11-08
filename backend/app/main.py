"""FastAPI application factory and lifespan management."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from backend import __version__
from backend.app.api import api_router
from backend.app.config import settings
from backend.app.database import SessionLocal, init_db
from backend.app.middleware import (
    RateLimitMiddleware,
    RequestIdMiddleware,
    install_exception_handlers,
    setup_logging,
)
from backend.services.task_queue import worker

logger = logging.getLogger("app")


def seed_demo_users() -> None:
    """Create the built-in default accounts on first startup."""
    from backend.app.models import User
    from backend.app.security import hash_password

    db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return
        demo = [
            ("admin", "Admin@12345", "admin"),
            ("analyst", "Analyst@12345", "analyst"),
            ("viewer", "Viewer@12345", "viewer"),
        ]
        for username, password, role in demo:
            db.add(User(username=username, password_hash=hash_password(password), role=role))
        db.commit()
        logger.info("seeded demo users: admin / analyst / viewer")
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    init_db()
    if settings.seed_demo:
        seed_demo_users()
    # 同步端点线程池上限（默认 40），与数据库连接池匹配
    import anyio.to_thread

    anyio.to_thread.current_default_thread_limiter().total_tokens = 128
    worker.start()
    logger.info("%s v%s started", settings.app_name, __version__)
    yield
    await worker.stop()


def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description="AI Agent 驱动的 Android 应用安全分析平台",
        lifespan=lifespan,
    )
    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(RateLimitMiddleware, limit_per_minute=settings.rate_limit_per_minute)
    install_exception_handlers(app)
    app.include_router(api_router)

    @app.get("/health", tags=["ops"])
    def health() -> dict:
        from backend.app.database import engine
        from sqlalchemy import text

        db_ok = True
        try:
            with engine.connect() as conn:
                conn.execute(text("SELECT 1"))
        except Exception:  # noqa: BLE001
            db_ok = False
        return {
            "status": "ok" if db_ok else "degraded",
            "app": settings.app_name,
            "version": __version__,
            "database": "up" if db_ok else "down",
            "worker": "running" if worker._running else "stopped",
            "queue_depth": worker.queue.qsize(),
            "llm": "configured" if settings.llm_api_key else "offline-engine",
        }

    return app


app = create_app()
