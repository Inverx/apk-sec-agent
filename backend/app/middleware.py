"""Global exception envelope, request validation errors, rate limiting and
log masking utilities."""

from __future__ import annotations

import json
import logging
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from contextvars import ContextVar

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.datastructures import MutableHeaders

from backend.app.config import settings

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")


class AppError(Exception):
    """Business error mapped to an HTTP status with a stable code."""

    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


class RateLimitMiddleware:
    """Sliding-window rate limiter keyed by client IP (pure ASGI, no
    BaseHTTPMiddleware overhead)."""

    def __init__(self, app, limit_per_minute: int | None = None) -> None:
        self.app = app
        self._init_limit = limit_per_minute
        self.window = 60.0
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    @property
    def limit(self) -> int:
        # read dynamically so tests / ops can tune without restart
        return settings.rate_limit_per_minute

    async def _reject(self, send, retry_after: int) -> None:
        body = json.dumps(
            {"code": "RATE_LIMITED", "message": "请求过于频繁，请稍后重试",
             "request_id": request_id_var.get()},
            ensure_ascii=False,
        ).encode("utf-8")
        headers = [
            (b"content-type", b"application/json; charset=utf-8"),
            (b"content-length", str(len(body)).encode("ascii")),
            (b"retry-after", str(retry_after).encode("ascii")),
        ]
        await send({"type": "http.response.start", "status": 429, "headers": headers})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http" or scope["path"] == "/health":
            await self.app(scope, receive, send)
            return

        limit = self.limit
        client = scope.get("client")
        remote = client[0] if client else "unknown"
        key = f"{remote}:{scope['method']}"
        now = time.monotonic()
        with self._lock:
            bucket = self._hits[key]
            while bucket and now - bucket[0] > self.window:
                bucket.popleft()
            if len(bucket) >= limit:
                retry_after = int(self.window - (now - bucket[0])) + 1
                limited = True
            else:
                bucket.append(now)
                limited = False
            if len(self._hits) > 10000:  # hard cap to avoid unbounded memory
                self._hits.clear()
        if limited:
            await self._reject(send, retry_after)
            return
        await self.app(scope, receive, send)

    def reset(self) -> None:
        """Clear all buckets (used by tests and ops tooling)."""
        with self._lock:
            self._hits.clear()


class RequestIdMiddleware:
    """Assigns a request id and timing headers (pure ASGI)."""

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request_id = new_request_id()
        token = request_id_var.set(request_id)
        started = time.perf_counter()

        async def send_wrapper(message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers.append("X-Request-ID", request_id)
                headers.append(
                    "X-Process-Time-Ms", f"{(time.perf_counter() - started) * 1000:.1f}"
                )
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            request_id_var.reset(token)


SECRET_PATTERNS = [
    (re.compile(r"(?i)(authorization\s*[(:]\s*)bearer\s+[A-Za-z0-9._\-]+"), r"\1Bearer ***"),
    (re.compile(
        r"""(?i)\b(access[_-]?token|refresh[_-]?token|api[_-]?key|password|passwd|pwd|secret)\b(['"]?\s*[=:]\s*['"]?)[^'"\s,;}]+""",
     ), r"\1\2***"),
    (re.compile(r"(?i)\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"), "***JWT***"),
]


def mask_secrets(text: str) -> str:
    for pattern, replacement in SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


class SecretMaskingFilter(logging.Filter):
    """Masks credentials in every log record before it reaches handlers."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        try:
            record.msg = mask_secrets(str(record.msg))
            if record.args:
                record.args = tuple(
                    mask_secrets(str(a)) if isinstance(a, str) else a for a in record.args
                )
        except Exception:  # noqa: BLE001 - never break logging
            pass
        return True


def setup_logging() -> None:
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s [%(request_id)s] %(name)s: %(message)s",
        defaults={"request_id": "-"},
    )

    class RequestIdFilter(logging.Filter):
        def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
            record.request_id = request_id_var.get()
            return True

    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    handler.addFilter(RequestIdFilter())
    handler.addFilter(SecretMaskingFilter())

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.INFO)
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "uvicorn.asgi"):
        lg = logging.getLogger(name)
        lg.handlers = [handler]
        lg.propagate = False
    # access log is per-request synchronous I/O; keep it for warnings only
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def app_error_handler(_: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"code": exc.code, "message": exc.message, "request_id": request_id_var.get()},
        )

    @app.exception_handler(RequestValidationError)
    async def validation_handler(_: Request, exc: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content={
                "code": "VALIDATION_ERROR",
                "message": "请求参数校验失败",
                "details": exc.errors()[:10],
                "request_id": request_id_var.get(),
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_handler(_: Request, exc: Exception) -> JSONResponse:
        logging.getLogger("app.error").exception("unhandled error: %s", exc)
        return JSONResponse(
            status_code=500,
            content={"code": "INTERNAL_ERROR", "message": "服务器内部错误",
                     "request_id": request_id_var.get()},
        )


def new_request_id() -> str:
    return uuid.uuid4().hex[:12]
