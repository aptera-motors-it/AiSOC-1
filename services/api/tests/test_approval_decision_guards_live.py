"""The approval decision route enforces its persisted authorization contract.

These cases use the ASGI route and a migrated Postgres database because a
decision is only safe when the database row, tenant-scoped session, and route
all agree on who may make it.
"""

from __future__ import annotations

import asyncio
import json
import os
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from app.api.v1.deps import CurrentUser, get_current_user
from app.api.v1.endpoints import approvals as endpoint
from app.db.rls import get_tenant_db, set_rls_context
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

DSN = os.environ.get("DATABASE_URL", "")
REQUIRED = os.environ.get("ADV_C_APPROVAL_GUARDS_REQUIRED", "").strip().lower() not in {"", "0", "false"}
TENANT = uuid.UUID("c0000000-0000-0000-0000-000000000001")
REQUESTER = uuid.UUID("c0000000-0000-0000-0000-000000000002")
REQUIRED_APPROVER = uuid.UUID("c0000000-0000-0000-0000-000000000003")
OTHER_APPROVER = uuid.UUID("c0000000-0000-0000-0000-000000000004")


@pytest_asyncio.fixture
async def session_factory() -> AsyncGenerator[async_sessionmaker[AsyncSession], None]:
    if "postgres" not in DSN:
        if REQUIRED:
            pytest.fail("ADV_C_APPROVAL_GUARDS_REQUIRED needs DATABASE_URL for a migrated Postgres database")
        pytest.skip("needs a migrated Postgres database")

    engine = create_async_engine(DSN, poolclass=NullPool)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1 FROM agent_approvals LIMIT 1"))
    except Exception as exc:
        await engine.dispose()
        if REQUIRED:
            pytest.fail(f"ADV_C_APPROVAL_GUARDS_REQUIRED could not reach migrated Postgres: {exc}")
        pytest.skip(f"no migrated Postgres database ({type(exc).__name__})")

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as db:
        await _seed(db)
    try:
        yield factory
    finally:
        async with factory() as db:
            await _cleanup(db)
        await engine.dispose()


async def _seed(db: AsyncSession) -> None:
    await _cleanup(db)
    await db.execute(
        text("INSERT INTO tenants (id, name, slug, plan) VALUES (:id, 'ADV-C Tenant', 'adv-c-tenant', 'enterprise')"),
        {"id": str(TENANT)},
    )
    for user_id, email in (
        (REQUESTER, "requester@adv-c.test"),
        (REQUIRED_APPROVER, "required@adv-c.test"),
        (OTHER_APPROVER, "other@adv-c.test"),
    ):
        await db.execute(
            text(
                """
                INSERT INTO users (id, tenant_id, email, username, hashed_password, role)
                VALUES (:id, :tenant_id, :email, :username, 'not-used', 'admin')
                """
            ),
            {"id": str(user_id), "tenant_id": str(TENANT), "email": email, "username": email.split("@")[0]},
        )
    await db.commit()


async def _cleanup(db: AsyncSession) -> None:
    ids = [str(REQUESTER), str(REQUIRED_APPROVER), str(OTHER_APPROVER)]
    await db.execute(text("DELETE FROM agent_approvals WHERE tenant_id = :tenant_id"), {"tenant_id": str(TENANT)})
    await db.execute(text("DELETE FROM users WHERE id = ANY(:ids)"), {"ids": ids})
    await db.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": str(TENANT)})
    await db.commit()


@pytest.fixture
def client(session_factory: async_sessionmaker[AsyncSession]) -> TestClient:
    actor = {"user_id": REQUIRED_APPROVER}
    app = FastAPI()
    app.include_router(endpoint.router, prefix="/api/v1")

    async def _db() -> AsyncGenerator[AsyncSession, None]:
        async with session_factory() as db:
            await set_rls_context(db, TENANT)
            yield db

    def _user() -> CurrentUser:
        user_id = actor["user_id"]
        return CurrentUser(
            user_id=user_id,
            tenant_id=TENANT,
            role="admin",
            email=f"{user_id}@adv-c.test",
            resolved_permissions=frozenset({"cases:write"}),
        )

    app.dependency_overrides[get_tenant_db] = _db
    app.dependency_overrides[get_current_user] = _user
    test_client = TestClient(app, raise_server_exceptions=False)
    test_client.actor = actor  # type: ignore[attr-defined]
    return test_client


async def _approval(
    session_factory: async_sessionmaker[AsyncSession],
    *,
    requester: uuid.UUID = REQUESTER,
    required_user_id: uuid.UUID | None = REQUIRED_APPROVER,
    expires_at: datetime | None = None,
    approval_status: str = "pending",
) -> uuid.UUID:
    approval_id = uuid.uuid4()
    action = json.dumps({"requester_principal": {"user_id": str(requester)}})
    async with session_factory() as db:
        await set_rls_context(db, TENANT)
        await db.execute(
            text(
                """
                INSERT INTO agent_approvals
                    (id, tenant_id, requested_by, required_user_id, title, summary, risk_level, action, status, expires_at)
                VALUES
                    (:id, :tenant_id, 'agent', :required_user_id, 'ADV-C decision', 'approval guard regression',
                     'high', CAST(:action AS jsonb), :status, :expires_at)
                """
            ),
            {
                "id": str(approval_id),
                "tenant_id": str(TENANT),
                "required_user_id": str(required_user_id) if required_user_id else None,
                "action": action,
                "status": approval_status,
                "expires_at": expires_at,
            },
        )
        await db.commit()
    return approval_id


def _decide(client: TestClient, approval_id: uuid.UUID, actor: uuid.UUID) -> int:
    client.actor["user_id"] = actor  # type: ignore[attr-defined]
    return client.post(f"/api/v1/approvals/{approval_id}/decide", json={"decision": "approve"}).status_code


@pytest.mark.integration
def test_requester_cannot_decide_own_approval(client: TestClient, session_factory) -> None:
    approval_id = asyncio.run(_approval(session_factory))

    assert _decide(client, approval_id, REQUESTER) == 403


@pytest.mark.integration
def test_only_the_required_user_can_decide(client: TestClient, session_factory) -> None:
    approval_id = asyncio.run(_approval(session_factory))

    assert _decide(client, approval_id, OTHER_APPROVER) == 403


@pytest.mark.integration
def test_expired_approval_cannot_be_decided(client: TestClient, session_factory) -> None:
    approval_id = asyncio.run(_approval(session_factory, expires_at=datetime.now(UTC) - timedelta(seconds=1)))

    assert _decide(client, approval_id, REQUIRED_APPROVER) == 409


@pytest.mark.integration
def test_non_pending_approval_cannot_be_decided_again(client: TestClient, session_factory) -> None:
    approval_id = asyncio.run(_approval(session_factory, approval_status="approved"))

    assert _decide(client, approval_id, REQUIRED_APPROVER) == 409


@pytest.mark.integration
def test_required_non_requester_can_decide_unexpired_pending_approval(client: TestClient, session_factory) -> None:
    approval_id = asyncio.run(_approval(session_factory, expires_at=datetime.now(UTC) + timedelta(minutes=1)))

    assert _decide(client, approval_id, REQUIRED_APPROVER) == 200
