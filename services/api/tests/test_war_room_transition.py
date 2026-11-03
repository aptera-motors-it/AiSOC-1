"""A war-room resolve follows the same transition table as the console.

The console refuses a status move that is not an edge in
``case_status.TRANSITIONS``. ``POST /war-rooms/{id}/decision`` with
``decision=resolve`` used to write ``status = 'resolved'`` for any current
status, so a case that was still ``new`` became resolved from chat.

Live PostgreSQL and the shipped ASGI app. The decision route is the path
the bot calls, and the row it updates is the row the console reads.
"""

from __future__ import annotations

import os
import socket
import uuid
from typing import Any
from urllib.parse import urlparse

import pytest
import pytest_asyncio
from app.main import app
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

_DSN = os.environ.get("DATABASE_URL", "")
_OWNER_DSN = os.environ.get("DATABASE_MIGRATION_URL", "").strip() or _DSN
_REQUIRED = os.environ.get("WAR_ROOM_TRANSITION_PROOF_REQUIRED", "").strip() not in ("", "0", "false")
_TOKEN = "war-room-transition-proof-token"


def _postgres_is_listening(dsn: str) -> bool:
    parsed = urlparse(dsn.replace("postgresql+asyncpg://", "postgresql://"))
    if not parsed.hostname:
        return False
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 5432), timeout=2):
            return True
    except OSError:
        return False


_LIVE = ("postgres" in _DSN and _postgres_is_listening(_DSN)) or _REQUIRED

live_only = pytest.mark.skipif(
    not _LIVE,
    reason="needs a live PostgreSQL with the migration chain applied",
)


@pytest_asyncio.fixture(autouse=True)
async def _release_the_app_pool():
    yield
    if _LIVE:
        from app.db.database import engine

        await engine.dispose()


async def _seed(status: str) -> tuple[Any, Any, uuid.UUID, uuid.UUID, uuid.UUID]:
    engine = create_async_engine(_OWNER_DSN)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    tenant_id = uuid.uuid4()
    case_id = uuid.uuid4()
    room_id = uuid.uuid4()
    suffix = tenant_id.hex[:8]
    async with maker() as db:
        await db.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": tenant_id, "n": f"war-room-{suffix}", "s": f"war-room-{suffix}"},
        )
        await db.execute(
            text(
                "INSERT INTO aisoc_cases (id, tenant_id, case_number, title, severity, status) "
                "VALUES (:i, :t, :n, 'Suspected intrusion', 'high', :status)"
            ),
            {"i": case_id, "t": tenant_id, "n": f"CASE-{suffix}", "status": status},
        )
        await db.execute(
            text(
                "INSERT INTO aisoc_case_war_rooms "
                "(id, tenant_id, case_id, provider, channel_id, channel_name, state, opened_by) "
                "VALUES (:i, :t, :c, 'slack', :ch, 'incident', 'open', 'ada@example.com')"
            ),
            {"i": room_id, "t": tenant_id, "c": case_id, "ch": f"C{suffix}"},
        )
        await db.commit()
    return engine, maker, tenant_id, case_id, room_id


async def _cleanup(maker: Any, tenant_id: uuid.UUID) -> None:
    async with maker() as db:
        await db.execute(text("SELECT set_config('app.audit_retention_purge', 'on', true)"))
        await db.execute(text("DELETE FROM audit_log WHERE tenant_id = :t"), {"t": tenant_id})
        await db.execute(text("DELETE FROM aisoc_cases WHERE tenant_id = :t"), {"t": tenant_id})
        await db.execute(text("DELETE FROM tenants WHERE id = :t"), {"t": tenant_id})
        await db.commit()


async def _case_row(maker: Any, case_id: uuid.UUID) -> Any:
    async with maker() as db:
        return (
            (
                await db.execute(
                    text("SELECT status, resolved_at FROM aisoc_cases WHERE id = :i"),
                    {"i": case_id},
                )
            )
            .mappings()
            .one()
        )


async def _post_count(maker: Any, room_id: uuid.UUID) -> int:
    async with maker() as db:
        return (
            await db.execute(
                text("SELECT count(*) FROM aisoc_war_room_posts WHERE war_room_id = :i"),
                {"i": room_id},
            )
        ).scalar_one()


async def _decide(room_id: uuid.UUID) -> tuple[int, dict[str, Any]]:
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post(
            f"/api/v1/war-rooms/{room_id}/decision",
            json={"decision": "resolve", "actor": "ada@example.com", "note": "host isolated"},
            headers={"X-AiSOC-Service-Token": _TOKEN},
        )
    try:
        body = res.json()
    except ValueError:
        body = {"raw": res.text}
    return res.status_code, body


@live_only
@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "allowed"),
    [
        ("new", False),
        ("triaged", False),
        ("investigating", True),
        ("contained", True),
        ("resolved", False),
        ("closed", False),
    ],
)
async def test_war_room_resolve_follows_the_transition_table(monkeypatch: pytest.MonkeyPatch, status: str, allowed: bool) -> None:
    """Resolve is a transition to ``resolved``, not a write that skips the table."""
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", _TOKEN)
    engine, maker, tenant_id, case_id, room_id = await _seed(status)
    try:
        code, body = await _decide(room_id)
        row = await _case_row(maker, case_id)
        posts = await _post_count(maker, room_id)
        if allowed:
            assert code == 200, body
            assert body["changed"]["status"] == "resolved"
            assert row["status"] == "resolved"
            assert row["resolved_at"] is not None
            assert posts == 1
        else:
            assert code == 422, body
            assert row["status"] == status
            assert row["resolved_at"] is None
            assert posts == 0
    finally:
        await _cleanup(maker, tenant_id)
        await engine.dispose()
