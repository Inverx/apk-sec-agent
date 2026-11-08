"""Middleware, health, and log masking tests."""

from __future__ import annotations

import pytest

from backend.app.middleware import mask_secrets


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["database"] == "up"
    assert payload["worker"] == "running"
    assert "version" in payload


def test_mask_bearer_token():
    text = 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123xyz "token"'
    masked = mask_secrets(text)
    assert "eyJhbGciOiJIUzI1NiJ9" not in masked
    assert "Bearer ***" in masked


def test_mask_password_fields():
    masked = mask_secrets('{"password": "hunter2secret", "username": "bob"}')
    assert "hunter2secret" not in masked
    assert "bob" in masked


def test_mask_jwt_shape():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    masked = mask_secrets(f"leaked {jwt} end")
    assert jwt not in masked
    assert "***JWT***" in masked


def test_rate_limit_returns_429(client, monkeypatch):
    from backend.app.config import settings
    from backend.app.middleware import RateLimitMiddleware

    monkeypatch.setattr(settings, "rate_limit_per_minute", 3)

    node = client.app.middleware_stack
    limiter = None
    while node is not None:
        if isinstance(node, RateLimitMiddleware):
            limiter = node
            break
        node = getattr(node, "app", None)
    assert limiter is not None
    limiter.reset()

    codes = []
    for _ in range(5):
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "nobody", "password": "wrong-password"},
        )
        codes.append(response.status_code)
    assert codes[:3] == [401, 401, 401]
    assert codes[3] == 429
    assert codes[4] == 429
    limited = client.post(
        "/api/v1/auth/login", json={"username": "nobody", "password": "wrong-password"}
    )
    assert limited.json()["code"] == "RATE_LIMITED"
    limiter.reset()


def test_validation_error_envelope(client):
    response = client.post("/api/v1/auth/register", json={"username": "x", "password": "1"})
    assert response.status_code == 422
    payload = response.json()
    assert payload["code"] == "VALIDATION_ERROR"
    assert "request_id" in payload


def test_request_id_header(client):
    response = client.get("/health")
    assert response.headers.get("X-Request-ID")
    assert response.headers.get("X-Process-Time-Ms")


def test_unknown_task_returns_404_envelope(client):
    from tests.conftest import auth_header, login, register

    register(client, "env-admin", "Password#123")
    token = login(client, "env-admin", "Password#123")
    response = client.get("/api/v1/tasks/nonexistent-id", headers=auth_header(token))
    assert response.status_code == 404
    assert response.json()["code"] == "TASK_NOT_FOUND"
