"""Shared FastAPI dependencies: auth + RBAC."""

from __future__ import annotations

from typing import Callable

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from backend.app.database import get_db
from backend.app.middleware import AppError
from backend.app.models import User
from backend.app.security import decode_access_token

bearer_scheme = HTTPBearer(auto_error=False)


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None or not credentials.credentials:
        raise AppError(401, "NOT_AUTHENTICATED", "缺少认证凭据")
    payload = decode_access_token(credentials.credentials)
    if payload is None:
        raise AppError(401, "INVALID_TOKEN", "令牌无效或已过期")
    user = db.get(User, str(payload.get("sub", "")))
    if user is None or not user.is_active:
        raise AppError(401, "USER_INACTIVE", "用户不存在或已被禁用")
    return user


def require_roles(*roles: str) -> Callable[..., User]:
    def dependency(user: User = Depends(get_current_user)) -> User:
        if user.role not in roles:
            raise AppError(403, "FORBIDDEN", f"角色 {user.role} 无权执行该操作")
        return user

    return dependency


require_admin = require_roles("admin")
require_analyst = require_roles("admin", "analyst")
require_viewer = require_roles("admin", "analyst", "viewer")
