"""API v1 routers."""

from __future__ import annotations

from fastapi import APIRouter

from backend.app.api import agent, apks, auth, tasks

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(auth.router)
api_router.include_router(apks.router)
api_router.include_router(tasks.router)
api_router.include_router(agent.router)
