"""`make demo` runs `python -m app.scripts.seed_demo` and that command must commit rows."""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
import uuid
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest
from app.api.v1.dev_auth import DEMO_TENANT_ID

_API_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_URL = "postgresql+asyncpg://aisoc:aisoc_dev_secret@127.0.0.1:5432/aisoc"


def _asyncpg_dsn(url: str, database: str) -> str:
    raw = url
    for prefix in ("postgresql+asyncpg://", "postgres+asyncpg://"):
        if raw.startswith(prefix):
            raw = "postgresql://" + raw[len(prefix) :]
            break
    if raw.startswith("postgres://"):
        raw = "postgresql://" + raw[len("postgres://") :]
    parts = urlsplit(raw)
    return urlunsplit((parts.scheme, parts.netloc, f"/{database}", "", ""))


def _sqlalchemy_url(asyncpg_dsn: str) -> str:
    return "postgresql+asyncpg://" + asyncpg_dsn[len("postgresql://") :]


async def _create_database(admin_dsn: str, name: str) -> None:
    conn = await asyncpg.connect(admin_dsn)
    try:
        await conn.execute(f'CREATE DATABASE "{name}"')
    finally:
        await conn.close()


async def _drop_database(admin_dsn: str, name: str) -> None:
    conn = await asyncpg.connect(admin_dsn)
    try:
        await conn.execute(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()",
            name,
        )
        await conn.execute(f'DROP DATABASE IF EXISTS "{name}"')
    finally:
        await conn.close()


async def _demo_counts(dsn: str) -> tuple[int, int]:
    conn = await asyncpg.connect(dsn)
    try:
        alerts = await conn.fetchval("SELECT count(*) FROM alerts WHERE tenant_id = $1", DEMO_TENANT_ID)
        cases = await conn.fetchval("SELECT count(*) FROM aisoc_cases WHERE tenant_id = $1", DEMO_TENANT_ID)
        return int(alerts), int(cases)
    finally:
        await conn.close()


def _run(module: str, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", module],
        cwd=_API_ROOT,
        env=env,
        text=True,
        capture_output=True,
        timeout=300,
        check=False,
    )


@pytest.mark.integration
def test_make_demo_seed_loads_rows() -> None:
    if not os.getenv("AISOC_RUN_INTEGRATION"):
        pytest.skip("set AISOC_RUN_INTEGRATION=1 to run the seed against Postgres")

    base = os.environ.get("DATABASE_URL") or _DEFAULT_URL
    name = f"aisoc_demo_seed_{uuid.uuid4().hex[:12]}"
    admin_dsn = _asyncpg_dsn(base, "postgres")
    target_dsn = _asyncpg_dsn(base, name)
    env = os.environ.copy()
    env.update(
        {
            "DATABASE_URL": _sqlalchemy_url(target_dsn),
            "DATABASE_MIGRATION_URL": _sqlalchemy_url(target_dsn),
            "ENVIRONMENT": "development",
            "SECRET_KEY": "ci-dummy-secret-key-at-least-32bytes!",
            "AISOC_ALLOW_SEED": "1",
            "AISOC_ALLOW_CLEARTEXT_DB": "true",
            "AISOC_MIGRATIONS_STRICT": "1",
            "OTEL_SDK_DISABLED": "true",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )

    asyncio.run(_create_database(admin_dsn, name))
    try:
        migrated = _run("app.scripts.run_migrations", env)
        assert migrated.returncode == 0, migrated.stderr[-4000:]
        seeded = _run("app.scripts.seed_demo", env)
        assert seeded.returncode == 0, seeded.stderr[-4000:]
        alerts, cases = asyncio.run(_demo_counts(target_dsn))
        assert alerts > 0
        assert cases > 0
    finally:
        asyncio.run(_drop_database(admin_dsn, name))
