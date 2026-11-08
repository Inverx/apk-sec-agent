"""JWT auth + RBAC tests."""

from __future__ import annotations

from tests.conftest import auth_header, login, register


def test_later_registrations_are_viewers(client, boot):
    response = client.post(
        "/api/v1/auth/register", json={"username": "later-viewer", "password": "Password#123"}
    )
    assert response.status_code == 201
    assert response.json()["role"] == "viewer"


def test_login_and_me(client, boot):
    me = client.get("/api/v1/auth/me", headers=auth_header(boot["viewer"]))
    assert me.status_code == 200
    assert me.json()["username"] == "boot-viewer"
    assert me.json()["role"] == "viewer"


def test_login_wrong_password(client, boot):
    response = client.post(
        "/api/v1/auth/login", json={"username": "boot-viewer", "password": "wrong-pass"}
    )
    assert response.status_code == 401
    assert response.json()["code"] == "BAD_CREDENTIALS"


def test_register_duplicate_username(client, boot):
    response = client.post(
        "/api/v1/auth/register", json={"username": "boot-admin", "password": "Password#123"}
    )
    assert response.status_code == 409
    assert response.json()["code"] == "USERNAME_TAKEN"


def test_me_requires_token(client):
    assert client.get("/api/v1/auth/me").status_code == 401
    assert client.get("/api/v1/auth/me", headers=auth_header("invalid.token.here")).status_code == 401


def test_admin_can_list_and_promote_users(client, boot):
    users = client.get("/api/v1/auth/users", headers=auth_header(boot["admin"]))
    assert users.status_code == 200
    assert {u["username"] for u in users.json()} >= {"boot-admin", "boot-analyst", "boot-viewer"}

    response = client.post(
        "/api/v1/auth/register", json={"username": "promote-me", "password": "Password#123"}
    )
    new_id = response.json()["id"]
    patched = client.patch(
        f"/api/v1/auth/users/{new_id}/role", json={"role": "analyst"},
        headers=auth_header(boot["admin"]),
    )
    assert patched.status_code == 200
    assert patched.json()["role"] == "analyst"


def test_admin_cannot_demote_self(client, boot):
    admin_user = client.get("/api/v1/auth/me", headers=auth_header(boot["admin"])).json()
    response = client.patch(
        f"/api/v1/auth/users/{admin_user['id']}/role", json={"role": "viewer"},
        headers=auth_header(boot["admin"]),
    )
    assert response.status_code == 400
    assert response.json()["code"] == "CANNOT_DEMOTE_SELF"


def test_viewer_cannot_upload_but_analyst_can(client, boot):
    denied = client.post(
        "/api/v1/apks/upload/init",
        json={"filename": "x.apk", "total_size": 10, "total_chunks": 1},
        headers=auth_header(boot["viewer"]),
    )
    assert denied.status_code == 403
    assert denied.json()["code"] == "FORBIDDEN"

    allowed = client.post(
        "/api/v1/apks/upload/init",
        json={"filename": "x.apk", "total_size": 10, "total_chunks": 1},
        headers=auth_header(boot["analyst"]),
    )
    assert allowed.status_code == 200


def test_viewer_cannot_export_report(client, boot):
    response = client.get("/api/v1/tasks/whatever/report.md", headers=auth_header(boot["viewer"]))
    assert response.status_code == 403


def test_non_admin_cannot_manage_users(client, boot):
    assert client.get("/api/v1/auth/users", headers=auth_header(boot["viewer"])).status_code == 403
    assert client.get("/api/v1/auth/users", headers=auth_header(boot["analyst"])).status_code == 403
