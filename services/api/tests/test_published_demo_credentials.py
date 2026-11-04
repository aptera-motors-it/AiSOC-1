"""Demo deploys must not keep serving a credential this repository publishes.

Two paths, both the ones a deploy actually runs:

* A published ``SECRET_KEY`` on ``ENVIRONMENT=demo`` is replaced with a
  per-process key before the boot check. The documented demo still starts,
  and the published string never signs a session. Production still refuses.
* ``seed_demo._ensure_user`` is what Railway runs on every deploy. It may set
  the published demo password when it creates the row. It must not write that
  hash again over a password an operator has since changed.
"""

from __future__ import annotations

import asyncio
import socket

import pytest
from app.core.config import INSECURE_SECRET_KEY_DEFAULTS, Settings, enforce_secure_defaults
from app.core.security import get_password_hash, verify_password
from app.models.tenant import Tenant, User
from app.scripts.seed_demo import _ensure_tenant, _ensure_user
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DEFAULT_SECRET = "change-me-in-production-at-least-32-chars"
OPERATOR_PASSWORD = "operator-chosen-password"
SEED_DSN = "postgresql+asyncpg://aisoc:aisoc@127.0.0.1:5432/aisoc_advh"


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "ENVIRONMENT": "demo",
        "ENV": "demo",
        "SECRET_KEY": "a" * 64,
        "METRICS_TOKEN": "long-random-token",
        "PLUGIN_TRUST_MODE": "strict",
        "AISOC_CREDENTIAL_KEY": "Z7t9fM3pZ8U_bN5oVxQYr1w2kLsHd4aJiTvE6cNxYpA=",
        "JWT_SECRET": "b" * 64,
        "REALTIME_INTERNAL_TOKEN": "c" * 64,
        "AISOC_REALTIME_JWT_SECRET": "d" * 64,
        "DATABASE_URL": "postgresql+asyncpg://aisoc:pw@db:5432/aisoc?sslmode=require",
    }
    base.update(overrides)
    return Settings(_env_file=None, **base)


def test_a_published_demo_secret_key_is_replaced_before_the_boot_check() -> None:
    """The documented demo starts. The published string does not sign it.

    Substitution happens when ``Settings`` is built, so the boot gate no
    longer sees a placeholder and does not refuse the process for this key.
    """
    settings = _settings(SECRET_KEY=DEFAULT_SECRET)
    assert settings.SECRET_KEY != DEFAULT_SECRET
    assert settings.SECRET_KEY not in INSECURE_SECRET_KEY_DEFAULTS
    assert enforce_secure_defaults(settings) == []


def test_demo_with_a_real_secret_key_still_boots_the_check() -> None:
    assert enforce_secure_defaults(_settings()) == []


def _postgres_accepts() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 5432), timeout=1):
            return True
    except OSError:
        return False


def test_a_second_seed_does_not_reset_the_demo_password() -> None:
    """The seed function, against Postgres, twice.

    The API unit job has no database, so this skips when nothing is listening
    rather than reporting a connection error as a seed failure. Where Postgres
    is up, the second call is the defect: it used to hash ``aisoc-demo`` onto
    the row again.
    """
    if not _postgres_accepts():
        pytest.skip("Postgres is not accepting connections on 127.0.0.1:5432")

    async def once() -> None:
        engine = create_async_engine(SEED_DSN)
        try:
            async with engine.begin() as conn:
                await conn.run_sync(Tenant.__table__.create, checkfirst=True)
                await conn.run_sync(User.__table__.create, checkfirst=True)
            session_factory = async_sessionmaker(engine, expire_on_commit=False)
            async with session_factory() as session:
                tenant = await _ensure_tenant(session)
                created = await _ensure_user(session, tenant)
                await session.commit()
                assert verify_password("aisoc-demo", created.hashed_password)

                created.hashed_password = get_password_hash(OPERATOR_PASSWORD)
                chosen = created.hashed_password
                await session.commit()

                again = await _ensure_user(session, tenant)
                await session.commit()
                assert again.hashed_password == chosen
                assert verify_password(OPERATOR_PASSWORD, again.hashed_password)
                assert not verify_password("aisoc-demo", again.hashed_password)
        finally:
            await engine.dispose()

    asyncio.run(once())
