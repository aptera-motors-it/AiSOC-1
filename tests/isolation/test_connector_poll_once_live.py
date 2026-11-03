"""One replica fetches a connector per window, against real Postgres.

Election is off, which is the default. Both schedulers still load the
poll job. A local stub vendor counts ``fetch_alerts``. The second
scheduler's poll in the same window must not reach the vendor. Once
the holder has stopped, that second poll must reach the vendor.

Skips when neither ``ISOLATION_CONNECTOR_DSN`` nor ``ISOLATION_LEASE_DSN``
is set. The workflow that owns this suite sets one of them.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import threading
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

import pytest

os.environ.setdefault("AISOC_CREDENTIAL_KEY", base64.urlsafe_b64encode(os.urandom(32)).decode())
os.environ.setdefault("AISOC_SERVICE_TOKEN", "poll-once-token-0123456789abcdef")

pytestmark = pytest.mark.skipif(
    not (os.environ.get("ISOLATION_CONNECTOR_DSN", "").strip() or os.environ.get("ISOLATION_LEASE_DSN", "").strip()),
    reason="ISOLATION_CONNECTOR_DSN is not set; this suite needs a live Postgres",
)


def _dsn() -> str:
    value = os.environ.get("ISOLATION_CONNECTOR_DSN", "").strip() or os.environ.get("ISOLATION_LEASE_DSN", "").strip()
    if not value:
        pytest.skip("ISOLATION_CONNECTOR_DSN is not set; this suite needs a live Postgres")
    if value.startswith("postgresql://") and not value.startswith("postgresql+"):
        return value.replace("postgresql://", "postgresql+asyncpg://", 1)
    return value


class _Ingest(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length) or b"{}")
        raw = json.dumps({"accepted": len(body.get("events", [])), "rejected": 0}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def _ingest_url() -> tuple[HTTPServer, str]:
    server = HTTPServer(("127.0.0.1", 0), _Ingest)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}"


def _stub_vendor():
    from app.connectors.base import BaseConnector, ConnectorSchema

    class StubVendor(BaseConnector):
        connector_id = "stub_vendor"
        connector_name = "Stub vendor"
        connector_category = "siem"
        fetches: list[str] = []

        @classmethod
        def schema(cls) -> ConnectorSchema:
            return ConnectorSchema(
                connector_id=cls.connector_id,
                connector_name=cls.connector_name,
                category=cls.connector_category,
                description="Local stub vendor.",
                fields=[],
            )

        async def test_connection(self) -> dict[str, bool]:
            return {"ok": True}

        async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, str]]:
            del since_seconds
            type(self).fetches.append("fetch")
            return [{"id": "evt-1", "message": "one"}]

    return StubVendor


async def _seed(engine: Any, connector_id: uuid.UUID) -> None:
    from sqlalchemy import text

    tenant_id = uuid.uuid4()
    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM scheduler_leases"))
        await conn.execute(text("UPDATE connectors SET is_enabled = FALSE"))
        await conn.execute(
            text("INSERT INTO tenants (id, name, slug) VALUES (:i, :n, :s)"),
            {"i": tenant_id, "n": f"poll-{tenant_id.hex[:8]}", "s": f"poll-{tenant_id.hex[:8]}"},
        )
        await conn.execute(
            text(
                "INSERT INTO connectors "
                "(id, tenant_id, connector_type, name, is_enabled, auth_config, connector_config) "
                "VALUES (:i, :t, 'stub_vendor', 'stub', true, '{}'::jsonb, CAST(:c AS jsonb))"
            ),
            {"i": connector_id, "t": tenant_id, "c": json.dumps({"poll_interval_seconds": 300})},
        )


async def _drop(engine: Any, connector_id: uuid.UUID) -> None:
    from sqlalchemy import text

    async with engine.begin() as conn:
        await conn.execute(text("DELETE FROM connectors WHERE id = :i"), {"i": connector_id})
        await conn.execute(
            text("DELETE FROM scheduler_leases WHERE scope = :s"),
            {"s": f"connector-poll:{connector_id}"},
        )


async def _run() -> tuple[list[bool], int, int, int]:
    from app.connectors import CONNECTOR_REGISTRY
    from app.ingest_client import IngestClient
    from app.scheduler import ConnectorScheduler, _job_id
    from app.security.credential_vault import get_vault
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    vendor = _stub_vendor()
    vendor.fetches = []
    CONNECTOR_REGISTRY["stub_vendor"] = vendor
    os.environ["AISOC_SCHEDULER_LEADER_ELECTION"] = "false"

    server, url = _ingest_url()
    engine = create_async_engine(_dsn())
    connector_id = uuid.uuid4()
    schedulers: list[ConnectorScheduler] = []
    try:
        await _seed(engine, connector_id)
        jobs: list[bool] = []
        for _replica in range(2):
            scheduler = ConnectorScheduler(
                engine=engine,
                ingest_client=IngestClient(url),
                vault=get_vault(),
            )
            schedulers.append(scheduler)
            await scheduler.start()
            job = scheduler._scheduler.get_job(_job_id(connector_id)) if scheduler._scheduler is not None else None
            jobs.append(job is not None)
            await scheduler._poll_one(connector_id=connector_id)
        in_window = len(vendor.fetches)
        async with engine.begin() as conn:
            await conn.execute(
                text("UPDATE scheduler_leases SET expires_at = now() - interval '1 second' WHERE scope = :s"),
                {"s": f"connector-poll:{connector_id}"},
            )
        await schedulers[0]._poll_one(connector_id=connector_id)
        fetched_before_stop = len(vendor.fetches)
        await schedulers[0].stop()
        await schedulers[1]._poll_one(connector_id=connector_id)
        return jobs, in_window, fetched_before_stop - in_window, len(vendor.fetches) - fetched_before_stop
    finally:
        for scheduler in schedulers:
            await scheduler.stop()
        await _drop(engine, connector_id)
        await engine.dispose()
        server.shutdown()
        CONNECTOR_REGISTRY.pop("stub_vendor", None)


def test_two_schedulers_fetch_the_stub_vendor_once_per_window() -> None:
    jobs, in_window, after_expiry, after_stop = asyncio.run(_run())
    assert jobs == [True, True], jobs
    assert in_window == 1, in_window
    assert after_expiry == 1, after_expiry
    assert after_stop == 1, after_stop
