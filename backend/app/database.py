"""SQLAlchemy 2.0 engine / session management."""

from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from backend.app.config import settings


class Base(DeclarativeBase):
    """Declarative base for all ORM models."""


_connect_args = {}
_pool_kwargs: dict = {}
if settings.database_url.startswith("sqlite"):
    _connect_args["check_same_thread"] = False
    # 同步端点跑在 anyio 线程池中，默认 QueuePool(5+10) 会在 32 并发下排队；
    # 显式放宽以匹配压测负载。
    _pool_kwargs = {"pool_size": 48, "max_overflow": 96, "pool_pre_ping": True}
else:
    _pool_kwargs = {"pool_pre_ping": True, "pool_size": 20, "max_overflow": 40}

engine = create_engine(settings.database_url, connect_args=_connect_args, **_pool_kwargs)

SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    from backend.app import models  # noqa: F401  (register mappers)

    Base.metadata.create_all(engine)
