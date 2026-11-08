"""Auth endpoints: register / login / me / user management."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app.api.deps import get_current_user, require_admin
from backend.app.database import get_db
from backend.app.middleware import AppError
from backend.app.models import User
from backend.app.schemas import LoginIn, RegisterIn, RoleUpdateIn, TokenOut, UserOut
from backend.app.security import create_access_token, hash_password, verify_password

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/register", response_model=UserOut, status_code=201)
def register(body: RegisterIn, db: Session = Depends(get_db)) -> User:
    existing = db.query(User).filter(User.username == body.username).first()
    if existing is not None:
        raise AppError(409, "USERNAME_TAKEN", "用户名已被注册")
    is_first = db.query(User).count() == 0
    user = User(
        username=body.username,
        password_hash=hash_password(body.password),
        role="admin" if is_first else "viewer",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenOut)
def login(body: LoginIn, db: Session = Depends(get_db)) -> TokenOut:
    user = db.query(User).filter(User.username == body.username).first()
    if user is None or not verify_password(body.password, user.password_hash):
        raise AppError(401, "BAD_CREDENTIALS", "用户名或密码错误")
    if not user.is_active:
        raise AppError(403, "USER_INACTIVE", "账号已被禁用")
    token = create_access_token(user.id, user.role)
    return TokenOut(access_token=token, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user


@router.get("/users", response_model=list[UserOut])
def list_users(_: User = Depends(require_admin), db: Session = Depends(get_db)) -> list[User]:
    return db.query(User).order_by(User.created_at).all()


@router.patch("/users/{user_id}/role", response_model=UserOut)
def update_role(user_id: str, body: RoleUpdateIn, admin: User = Depends(require_admin),
                db: Session = Depends(get_db)) -> User:
    user = db.get(User, user_id)
    if user is None:
        raise AppError(404, "USER_NOT_FOUND", "用户不存在")
    if user.id == admin.id and body.role != "admin":
        raise AppError(400, "CANNOT_DEMOTE_SELF", "不能降级自己的管理员角色")
    user.role = body.role
    db.commit()
    db.refresh(user)
    return user
