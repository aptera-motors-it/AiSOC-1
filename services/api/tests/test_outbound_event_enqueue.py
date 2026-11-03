"""An enabled destination receives the status moves it subscribes to.

``enqueue_event`` queues one delivery per enabled destination whose
subscription includes the event (an empty subscription means every event).
Nothing outside the tests calls it, so a destination that is enabled and
then watches an alert or a case change status never gets a row.

The request goes through the shipped ASGI app: a real JWT, the alert and
case PATCH routes, and PostgreSQL with the migration chain applied. The
app connects as whatever ``DATABASE_URL`` names. Seeding uses
``DATABASE_MIGRATION_URL`` when that is set, so the owner can create the
scratch tenant while the runtime role stays the one the request uses.
"""

from __future__ import annotations

import json
import os
import socket
import uuid
from urllib.parse import urlparse

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

_OWNER_DSN = os.environ.get("DATABASE_MIGRATION_URL", "").strip() or os.environ.get("DATABASE_URL", "")
_REQUIRED = os.environ.get("OUTBOUND_ENQUEUE_PROOF_REQUIRED", "").strip() not in ("", "0", "false")

_UNUSABLE_PASSWORD_HASH = "x"  # noqa: S105 - not a credential; no plaintext maps to it

ALERT_STATUS_CHANGED = "alert.status_changed"
CASE_STATUS_CHANGED = "case.status_changed"


def _postgres_is_listening() -> bool:
    parsed = urlparse(_OWNER_DSN.replace("postgresql+asyncpg://", "postgresql://"))
    if not parsed.hostname:
        return False
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 5432), timeout=2):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not ("postgres" in _OWNER_DSN and _postgres_is_listening()) and not _REQUIRED,
    reason="needs a live PostgreSQL with the migration chain applied",
)


@pytest_asyncio.fixture(autouse=True)
async def _release_the_app_pool():
    yield
    from app.db.database import engine

    await engine.dispose()


@pytest_asyncio.fixture
async def world():
    """Two tenants, one analyst each, and one open alert on the first."""
    from app.core.security import create_access_token

    engine = create_async_engine(_OWNER_DSN)
    maker = async_sessionmaker(engine, expire_on_commit=False)

    tenant_id = uuid.uuid4()
    other_tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    other_user_id = uuid.uuid4()
    alert_id = uuid.uuid4()
    suffix = tenant_id.hex[:8]

    async with maker() as db:
        for tid, slug in ((tenant_id, f"enqueue-{suffix}"), (other_tenant_id, f"enqueue-other-{suffix}")):
            await db.execute(
                text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
                {"i": tid, "n": slug, "s": slug},
            )
        for uid, tid, name in ((user_id, tenant_id, "analyst"), (other_user_id, other_tenant_id, "other")):
            await db.execute(
                text(
                    """
                    INSERT INTO users (id, tenant_id, email, username, hashed_password,
                                       role, is_active, is_verified)
                    VALUES (:i, :t, :e, :u, :h, 'admin', TRUE, TRUE)
                    """
                ),
                {
                    "i": uid,
                    "t": tid,
                    "e": f"{name}-{suffix}@example.com",
                    "u": f"{name}-{suffix}",
                    "h": _UNUSABLE_PASSWORD_HASH,
                },
            )
        await db.execute(
            text(
                """
                INSERT INTO alerts (id, tenant_id, title, severity, status, priority, created_at, updated_at)
                VALUES (:i, :t, 'LSASS dump on DC01', 'critical', 'new', 40, NOW(), NOW())
                """
            ),
            {"i": alert_id, "t": tenant_id},
        )
        await db.commit()

    yield {
        "maker": maker,
        "tenant_id": tenant_id,
        "other_tenant_id": other_tenant_id,
        "alert_id": alert_id,
        "token": create_access_token({"sub": str(user_id)}),
        "other_token": create_access_token({"sub": str(other_user_id)}),
    }
    await engine.dispose()


async def _request(method: str, path: str, token: str, body: dict | None = None) -> tuple[int, dict]:
    from app.main import app

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        response = await client.request(
            method,
            path,
            json=body,
            headers={"Authorization": f"Bearer {token}", "user-agent": "enqueue-proof"},
        )
    payload: dict = {}
    if response.content:
        try:
            parsed = response.json()
        except ValueError:
            parsed = {"raw": response.text}
        payload = parsed if isinstance(parsed, dict) else {"raw": parsed}
    return response.status_code, payload


async def _deliveries(maker, tenant_id: uuid.UUID) -> list[dict]:
    async with maker() as db:
        rows = (
            (
                await db.execute(
                    text(
                        """
                        SELECT webhook_id, event_type, status, payload
                        FROM aisoc_outbound_deliveries
                        WHERE tenant_id = :t
                        ORDER BY created_at
                        """
                    ),
                    {"t": tenant_id},
                )
            )
            .mappings()
            .all()
        )
    out = []
    for row in rows:
        record = dict(row)
        record["webhook_id"] = str(record["webhook_id"])
        if isinstance(record["payload"], str):
            record["payload"] = json.loads(record["payload"])
        out.append(record)
    return out


async def _enable(token: str, *, name: str, event_types: list[str]) -> str:
    code, created = await _request(
        "POST",
        "/api/v1/outbound-webhooks",
        token,
        {"name": name, "url": "https://example.com/aisoc-hook", "event_types": event_types},
    )
    assert code == 201, created
    assert created["enabled"] is False
    code, updated = await _request(
        "PATCH",
        f"/api/v1/outbound-webhooks/{created['id']}",
        token,
        {"enabled": True},
    )
    assert code == 200 and updated["enabled"] is True, updated
    return str(created["id"])


async def test_enabled_destination_receives_subscribed_status_moves(world) -> None:
    maker = world["maker"]
    tenant_id = world["tenant_id"]
    alert_id = world["alert_id"]
    token = world["token"]

    alert_hook = await _enable(token, name="alert-siem", event_types=[ALERT_STATUS_CHANGED])
    case_hook = await _enable(token, name="case-siem", event_types=[CASE_STATUS_CHANGED])
    code, disabled = await _request(
        "POST",
        "/api/v1/outbound-webhooks",
        token,
        {"name": "paused", "url": "https://example.com/aisoc-paused", "event_types": [ALERT_STATUS_CHANGED]},
    )
    assert code == 201 and disabled["enabled"] is False, disabled
    other_hook = await _enable(world["other_token"], name="other-tenant", event_types=[ALERT_STATUS_CHANGED])

    code, body = await _request("PATCH", f"/api/v1/alerts/{alert_id}", token, {"priority": 10})
    assert code == 200, body
    assert await _deliveries(maker, tenant_id) == []

    code, body = await _request("PATCH", f"/api/v1/alerts/{alert_id}", token, {"status": "triaging"})
    assert code == 200, body
    rows = await _deliveries(maker, tenant_id)
    assert rows == [
        {
            "webhook_id": alert_hook,
            "event_type": ALERT_STATUS_CHANGED,
            "status": "pending",
            "payload": {"alert_id": str(alert_id), "from_status": "new", "to_status": "triaging"},
        }
    ], f"an enabled destination subscribed to alert status moves received nothing when the alert moved. rows={rows}"

    code, body = await _request("PATCH", f"/api/v1/alerts/{alert_id}", token, {"status": "triaging"})
    assert code == 200, body
    assert await _deliveries(maker, tenant_id) == rows

    code, created = await _request(
        "POST",
        "/api/v1/cases",
        token,
        {"title": "Credential theft on DC01", "severity": "critical"},
    )
    assert code == 201, created
    assert await _deliveries(maker, tenant_id) == rows

    code, body = await _request("PATCH", f"/api/v1/cases/{created['id']}", token, {"status": "triaged"})
    assert code == 200, body
    rows = await _deliveries(maker, tenant_id)
    assert rows[1:] == [
        {
            "webhook_id": case_hook,
            "event_type": CASE_STATUS_CHANGED,
            "status": "pending",
            "payload": {"case_id": str(created["id"]), "from_status": "new", "to_status": "triaged"},
        }
    ], rows

    other_rows = await _deliveries(maker, world["other_tenant_id"])
    assert other_rows == []
    assert all(row["webhook_id"] not in {disabled["id"], other_hook} for row in rows)
