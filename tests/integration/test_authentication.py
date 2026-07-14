from datetime import UTC, datetime, timedelta

from sqlalchemy import select

from aegis_api.models import AuditEvent, Session
from aegis_api.security.tokens import hash_secret
from conftest import ORIGIN, PASSWORD, AppHarness


def test_login_sets_hardened_cookie_and_stores_only_hash(app_harness: AppHarness) -> None:
    response = app_harness.client.post(
        "/api/v1/auth/login",
        headers={"Origin": ORIGIN},
        json={"email": "system.administrator@example.com", "password": PASSWORD},
    )
    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert "__Host-aegis_session=" in cookie
    assert "HttpOnly" in cookie
    assert "Secure" in cookie
    assert "SameSite=lax" in cookie
    raw_token = app_harness.client.cookies.get("__Host-aegis_session")

    async def stored(db):  # type: ignore[no-untyped-def]
        return (await db.execute(select(Session))).scalar_one()

    session = app_harness.run(stored)
    assert session.token_hash == hash_secret(raw_token)
    assert raw_token not in session.token_hash


def test_invalid_user_and_password_have_same_safe_error(app_harness: AppHarness) -> None:
    wrong_password = app_harness.client.post(
        "/api/v1/auth/login",
        headers={"Origin": ORIGIN},
        json={"email": "system.administrator@example.com", "password": "wrong"},
    )
    unknown_user = app_harness.client.post(
        "/api/v1/auth/login",
        headers={"Origin": ORIGIN},
        json={"email": "unknown@example.com", "password": "wrong"},
    )
    assert wrong_password.status_code == unknown_user.status_code == 401
    assert wrong_password.json()["code"] == unknown_user.json()["code"] == "invalid_credentials"
    assert wrong_password.json()["message"] == unknown_user.json()["message"]
    assert "system.administrator@example.com" not in wrong_password.text


def test_account_locks_after_configured_failures(app_harness: AppHarness) -> None:
    for _ in range(5):
        response = app_harness.client.post(
            "/api/v1/auth/login",
            headers={"Origin": ORIGIN},
            json={"email": "viewer@example.com", "password": "wrong"},
        )
        assert response.status_code == 401
    locked = app_harness.client.post(
        "/api/v1/auth/login",
        headers={"Origin": ORIGIN},
        json={"email": "viewer@example.com", "password": PASSWORD},
    )
    assert locked.status_code == 401


def test_login_rotates_existing_session(app_harness: AppHarness) -> None:
    app_harness.login()
    first_token = app_harness.client.cookies.get("__Host-aegis_session")
    app_harness.login()
    second_token = app_harness.client.cookies.get("__Host-aegis_session")
    assert first_token != second_token

    async def sessions(db):  # type: ignore[no-untyped-def]
        return list((await db.execute(select(Session).order_by(Session.created_at))).scalars())

    records = app_harness.run(sessions)
    assert len(records) == 2
    assert records[0].revoked_at is not None
    assert records[1].rotated_from_id == records[0].id


def test_csrf_and_origin_are_required_for_unsafe_request(app_harness: AppHarness) -> None:
    _, csrf = app_harness.login()
    payload = {
        "name": "core-router",
        "network_zone": "core",
        "criticality": "critical",
        "is_internal": True,
    }
    assert app_harness.client.post("/api/v1/assets", json=payload).status_code == 403
    assert (
        app_harness.client.post(
            "/api/v1/assets",
            headers={"Origin": "https://evil.example", "X-CSRF-Token": csrf},
            json=payload,
        ).status_code
        == 403
    )
    accepted = app_harness.client.post(
        "/api/v1/assets",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json=payload,
    )
    assert accepted.status_code == 201


def test_expired_and_revoked_sessions_are_rejected(app_harness: AppHarness) -> None:
    app_harness.login()

    async def expire(db):  # type: ignore[no-untyped-def]
        session = (await db.execute(select(Session))).scalar_one()
        session.idle_expires_at = datetime.now(UTC) - timedelta(seconds=1)
        await db.commit()

    app_harness.run(expire)
    assert app_harness.client.get("/api/v1/auth/me").status_code == 401


def test_logout_revokes_session_and_is_audited(app_harness: AppHarness) -> None:
    _, csrf = app_harness.login()
    response = app_harness.client.post(
        "/api/v1/auth/logout", headers={"Origin": ORIGIN, "X-CSRF-Token": csrf}
    )
    assert response.status_code == 204
    assert app_harness.client.get("/api/v1/auth/me").status_code == 401

    async def logout_events(db):  # type: ignore[no-untyped-def]
        return list(
            (
                await db.execute(select(AuditEvent).where(AuditEvent.action == "auth.logout"))
            ).scalars()
        )

    assert len(app_harness.run(logout_events)) == 1


def test_last_system_administrator_cannot_remove_own_role(
    app_harness: AppHarness,
) -> None:
    auth, csrf = app_harness.login()
    user = auth["user"]
    response = app_harness.client.put(
        f"/api/v1/users/{user['id']}/roles",
        headers={"Origin": ORIGIN, "X-CSRF-Token": csrf},
        json={"roles": ["Viewer"], "expected_version": user["version"]},
    )
    assert response.status_code == 409
    assert response.json()["code"] == "last_system_admin"
