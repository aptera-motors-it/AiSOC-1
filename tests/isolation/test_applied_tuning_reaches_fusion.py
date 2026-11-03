from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
import pytest_asyncio

if TYPE_CHECKING:
    import httpx
    from sqlalchemy.ext.asyncio import AsyncSession

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "services" / "api"))

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_TUNING_DSN", "").strip(),
        reason="ISOLATION_TUNING_DSN is not set; this suite needs a live Postgres",
    ),
]

_PASSPHRASE = "tuning-floor-passphrase-42"
_HOST = "WIN-FS01"
_SEVERITY = "high"

_FUSION = r"""
import asyncio
import json
import sys

import asyncpg
from app.services.detection_engine import DetectionEngine
from app.services.tenant_overlay import OverlayCache

MATCH = {"host": "WIN-FS01", "event": "rename"}
SECOND = {"host": "WIN-FS02", "event": "rename"}
OTHER = {"host": "OTHER-01", "event": "rename"}


async def main() -> None:
    dsn, tenant, rule_id, severity = sys.argv[1:5]
    pool = await asyncpg.create_pool(dsn, min_size=1, max_size=1)
    overlay = await OverlayCache(pool, reload_seconds=0).get(tenant)
    rule = {
        "id": rule_id,
        "name": "Mass file rename",
        "severity": severity,
        "category": "impact",
        "match_when": {"event": "rename"},
    }
    engine = DetectionEngine(rules=[rule])
    match_event = {"ocsf_event": {"raw_data": json.dumps(MATCH)}}
    second_event = {"ocsf_event": {"raw_data": json.dumps(SECOND)}}
    other_event = {"ocsf_event": {"raw_data": json.dumps(OTHER)}}
    override = overlay.overrides.get(rule_id)
    print(
        json.dumps(
            {
                "hits": len(engine.evaluate(match_event, overlay)),
                "second_hits": len(engine.evaluate(second_event, overlay)),
                "other_hits": len(engine.evaluate(other_event, overlay)),
                "severity_floor": overlay.raises_severity_floor(rule_id, severity),
                "suppresses": overlay.suppresses(rule_id, MATCH),
                "enabled": None if override is None else override.enabled,
                "min_severity": None if override is None else override.min_severity,
            }
        )
    )
    await pool.close()


asyncio.run(main())
"""


def _dsn() -> str:
    return os.environ.get("ISOLATION_TUNING_DSN", "").strip()


def _app_dsn(raw: str) -> str:
    if raw.startswith("postgresql+asyncpg://") or raw.startswith("postgres+asyncpg://"):
        return raw
    if raw.startswith("postgresql://"):
        return "postgresql+asyncpg://" + raw[len("postgresql://") :]
    if raw.startswith("postgres://"):
        return "postgresql+asyncpg://" + raw[len("postgres://") :]
    return raw


def _asyncpg_dsn(raw: str) -> str:
    return raw.replace("postgresql+asyncpg://", "postgresql://", 1).replace("postgres+asyncpg://", "postgres://", 1)


def _prepare_env() -> None:
    os.environ["DATABASE_URL"] = _app_dsn(_dsn())
    os.environ["ENVIRONMENT"] = "test"
    os.environ["ENV"] = "test"
    os.environ["CLICKHOUSE_HOST"] = ""
    os.environ["AISOC_ALLOW_CLEARTEXT_DB"] = "1"


def _fusion(tenant: str, rule_id: str) -> dict:
    env = {
        "PYTHONPATH": str(REPO / "services" / "fusion"),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    proc = subprocess.run(
        [sys.executable, "-", _asyncpg_dsn(_dsn()), tenant, rule_id, _SEVERITY],
        input=_FUSION,
        text=True,
        capture_output=True,
        cwd=str(REPO / "services" / "fusion"),
        env=env,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr[-1500:]
    return json.loads(proc.stdout.strip().splitlines()[-1])


def _as_dict(value: object) -> dict:
    assert isinstance(value, dict), type(value)
    return value


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def app_client() -> AsyncIterator[httpx.AsyncClient]:
    pytest.importorskip("httpx")
    _prepare_env()
    import httpx
    from app.main import create_application

    transport = httpx.ASGITransport(app=create_application())
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest_asyncio.fixture(loop_scope="module")
async def db() -> AsyncIterator[AsyncSession]:
    pytest.importorskip("sqlalchemy")
    _prepare_env()
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    engine = create_async_engine(_app_dsn(_dsn()), future=True)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session
    await engine.dispose()


async def _tenant_and_rule(db: AsyncSession) -> tuple[uuid.UUID, uuid.UUID, str, dict[str, str]]:
    import sqlalchemy
    from app.core.security import get_password_hash

    tenant_id = uuid.uuid4()
    user_id = uuid.uuid4()
    rule_id = uuid.uuid4()
    source = f"det-tune-{uuid.uuid4().hex[:8]}"
    email = f"tune-{user_id.hex[:10]}@example.com"
    await db.execute(
        sqlalchemy.text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
        {"i": tenant_id, "n": f"tune-{tenant_id.hex[:8]}", "s": f"tune-{tenant_id.hex[:8]}"},
    )
    await db.execute(
        sqlalchemy.text(
            "INSERT INTO users (id, tenant_id, email, username, role, is_active, hashed_password) "
            "VALUES (:i, :t, :e, :u, 'admin', TRUE, :p)"
        ),
        {
            "i": user_id,
            "t": tenant_id,
            "e": email,
            "u": email.split("@", 1)[0],
            "p": get_password_hash(_PASSPHRASE),
        },
    )
    await db.execute(
        sqlalchemy.text(
            "INSERT INTO detection_rules "
            "(id, tenant_id, name, rule_language, rule_body, category, status, severity, provenance) "
            "VALUES (:i, :t, 'Mass file rename', 'sigma', 'title: mass rename', 'impact', 'active', :sev, CAST(:p AS jsonb))"
        ),
        {"i": rule_id, "t": tenant_id, "sev": _SEVERITY, "p": json.dumps({"source_id": source})},
    )
    await db.commit()
    return tenant_id, rule_id, source, {"email": email}


async def _bearer(client: httpx.AsyncClient, email: str) -> dict[str, str]:
    response = await client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": _PASSPHRASE},
    )
    assert response.status_code == 200, response.text
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


async def _stored(db: AsyncSession, rule_id: uuid.UUID) -> dict:
    import sqlalchemy

    await db.rollback()
    row = (
        (
            await db.execute(
                sqlalchemy.text("SELECT status, threshold_config, suppression_config FROM detection_rules WHERE id = :i"),
                {"i": rule_id},
            )
        )
        .mappings()
        .one()
    )
    return {
        "status": row["status"],
        "threshold": _as_dict(row["threshold_config"]),
        "suppression": _as_dict(row["suppression_config"]),
    }


async def test_raise_threshold_sets_the_severity_floor(app_client: httpx.AsyncClient, db: AsyncSession) -> None:
    tenant_id, rule_id, source, user = await _tenant_and_rule(db)
    before = _fusion(str(tenant_id), source)
    assert before["hits"] == 1, before
    assert before["severity_floor"] is None, before

    headers = await _bearer(app_client, user["email"])
    response = await app_client.post(
        f"/api/v1/detection/tuning/{rule_id}/apply",
        json={"action": "raise_threshold"},
        headers=headers,
    )
    assert response.status_code == 200, response.text

    stored = await _stored(db, rule_id)
    decision = _fusion(str(tenant_id), source)
    assert stored["status"] == "active", stored
    assert stored["threshold"].get("min_severity"), stored
    assert decision["enabled"] is True, decision
    assert decision["hits"] == 0, {"decision": decision, "stored": stored}
    assert decision["severity_floor"], {"decision": decision, "stored": stored}


async def test_add_suppression_reaches_fusion(app_client: httpx.AsyncClient, db: AsyncSession) -> None:
    tenant_id, rule_id, source, user = await _tenant_and_rule(db)
    before = _fusion(str(tenant_id), source)
    assert before["hits"] == 1, before
    assert before["suppresses"] is None, before

    headers = await _bearer(app_client, user["email"])
    response = await app_client.post(
        f"/api/v1/detection/tuning/{rule_id}/apply",
        json={
            "action": "add_suppression",
            "suppression_reason": "nightly rename",
            "suppress_when": {"host": [_HOST]},
        },
        headers=headers,
    )
    assert response.status_code == 200, response.text

    stored = await _stored(db, rule_id)
    decision = _fusion(str(tenant_id), source)
    assert stored["status"] == "active", stored
    assert _HOST in stored["suppression"].get("suppress_when", {}).get("host", []), stored
    assert decision["enabled"] is True, decision
    assert decision["suppresses"], {"decision": decision, "stored": stored}
    assert decision["hits"] == 0, {"decision": decision, "stored": stored}
    assert decision["other_hits"] == 1, {"decision": decision, "stored": stored}


async def test_concurrent_suppressions_both_reach_fusion(app_client: httpx.AsyncClient, db: AsyncSession) -> None:
    tenant_id, rule_id, source, user = await _tenant_and_rule(db)
    headers = await _bearer(app_client, user["email"])

    async def apply(host: str) -> httpx.Response:
        return await app_client.post(
            f"/api/v1/detection/tuning/{rule_id}/apply",
            json={
                "action": "add_suppression",
                "suppression_reason": host,
                "suppress_when": {"host": [host]},
            },
            headers=headers,
        )

    responses = await asyncio.gather(apply("WIN-FS01"), apply("WIN-FS02"))
    assert [response.status_code for response in responses] == [200, 200]

    stored = await _stored(db, rule_id)
    decision = _fusion(str(tenant_id), source)
    hosts = stored["suppression"].get("suppress_when", {}).get("host", [])
    assert set(hosts) == {"WIN-FS01", "WIN-FS02"}, stored
    assert len(stored["suppression"].get("rules", [])) == 2, stored
    assert decision["hits"] == 0, {"decision": decision, "stored": stored}
    assert decision["second_hits"] == 0, {"decision": decision, "stored": stored}
    assert decision["other_hits"] == 1, {"decision": decision, "stored": stored}
