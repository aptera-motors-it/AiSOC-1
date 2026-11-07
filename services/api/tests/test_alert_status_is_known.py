from __future__ import annotations

import os
import socket
import uuid
from urllib.parse import urlparse

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

_DSN = os.environ.get("DATABASE_MIGRATION_URL", "").strip() or os.environ.get("DATABASE_URL", "")
_REQUIRED = os.environ.get("ALERT_STATUS_PROOF_REQUIRED", "").strip() not in ("", "0", "false")


def _postgres_is_listening() -> bool:
    parsed = urlparse(_DSN.replace("postgresql+asyncpg://", "postgresql://"))
    if not parsed.hostname:
        return False
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 5432), timeout=2):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not ("postgres" in _DSN and _postgres_is_listening()) and not _REQUIRED,
    reason="needs a live PostgreSQL with the migration chain applied",
)

_UNUSABLE_PASSWORD_HASH = "x"  # noqa: S105


@pytest_asyncio.fixture(autouse=True)
async def _release_the_app_pool():
    yield
    from app.db.database import engine

    await engine.dispose()


@pytest_asyncio.fixture
async def world():
    from app.core.security import create_access_token

    engine = create_async_engine(_DSN)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    alert_id = uuid.uuid4()
    suffix = tenant_id.hex[:8]

    async with maker() as db:
        await db.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": tenant_id, "n": f"status-{suffix}", "s": f"status-{suffix}"},
        )
        await db.execute(
            text(
                """
                INSERT INTO users (id, tenant_id, email, username, hashed_password,
                                   role, is_active, is_verified)
                VALUES (:i, :t, :e, :u, :h, 'admin', TRUE, TRUE)
                """
            ),
            {
                "i": user_id,
                "t": tenant_id,
                "e": f"analyst-{suffix}@example.com",
                "u": f"analyst-{suffix}",
                "h": _UNUSABLE_PASSWORD_HASH,
            },
        )
        await db.execute(
            text(
                """
                INSERT INTO alerts (
                    id, tenant_id, title, severity, status, priority, created_at, updated_at
                )
                VALUES (
                    :i, :t, 'Suspicious sign-in from an unfamiliar ASN', 'critical', 'new', 40, NOW(), NOW()
                )
                """
            ),
            {"i": alert_id, "t": tenant_id},
        )
        await db.commit()

    token = create_access_token({"sub": str(user_id)})
    yield maker, alert_id, token
    await engine.dispose()


async def _patch(token: str, alert_id: uuid.UUID, body: dict) -> tuple[int, dict]:
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.patch(
            f"/api/v1/alerts/{alert_id}",
            json=body,
            headers={"Authorization": f"Bearer {token}"},
        )
    payload = response.json() if response.content else {}
    return response.status_code, payload if isinstance(payload, dict) else {"_raw": payload}


async def _unresolved(token: str) -> int:
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.get(
            "/api/v1/alerts",
            headers={"Authorization": f"Bearer {token}"},
        )
    assert response.status_code == 200, response.text
    return int(response.json()["facets"]["unresolved"])


async def _stored(maker, alert_id: uuid.UUID) -> tuple[str, object]:
    async with maker() as db:
        row = (
            await db.execute(
                text("SELECT status, resolved_at FROM alerts WHERE id = :i"),
                {"i": alert_id},
            )
        ).one()
    return str(row.status), row.resolved_at


async def test_an_unknown_status_is_refused_and_the_row_stays_open(world) -> None:
    maker, alert_id, token = world

    code, body = await _patch(token, alert_id, {"status": "banana"})

    assert code == 422, body
    status, resolved_at = await _stored(maker, alert_id)
    assert status == "new"
    assert resolved_at is None
    assert await _unresolved(token) == 1


async def test_a_false_positive_leaves_the_unresolved_facet(world) -> None:
    maker, alert_id, token = world

    code, body = await _patch(token, alert_id, {"status": "false_positive"})

    assert code == 200, body
    status, resolved_at = await _stored(maker, alert_id)
    assert status == "false_positive"
    assert resolved_at is not None
    assert await _unresolved(token) == 0


async def test_reopening_clears_resolved_at(world) -> None:
    maker, alert_id, token = world

    closed, closed_body = await _patch(token, alert_id, {"status": "resolved"})
    assert closed == 200, closed_body
    _, stamped = await _stored(maker, alert_id)
    assert stamped is not None

    reopened, reopened_body = await _patch(token, alert_id, {"status": "new"})
    assert reopened == 200, reopened_body
    status, resolved_at = await _stored(maker, alert_id)
    assert status == "new"
    assert resolved_at is None
    assert await _unresolved(token) == 1
