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


def _gated_vendor():
    from app.connectors.base import BaseConnector, ConnectorSchema

    class GatedVendor(BaseConnector):
        connector_id = "stub_vendor"
        connector_name = "Stub vendor"
        connector_category = "siem"
        fetches: list[str] = []
        in_flight = 0
        max_in_flight = 0
        hold: asyncio.Event | None = None
        entered: asyncio.Event | None = None

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
            vendor = type(self)
            vendor.fetches.append("fetch")
            vendor.in_flight += 1
            vendor.max_in_flight = max(vendor.max_in_flight, vendor.in_flight)
            try:
                if vendor.entered is not None:
                    vendor.entered.set()
                if vendor.hold is not None:
                    await vendor.hold.wait()
            finally:
                vendor.in_flight -= 1
            return [{"id": "evt-1", "message": "one"}]

    return GatedVendor


def _connector_id() -> uuid.UUID:
    # First fire is ``id.int % 60`` seconds out. Zero would poll during the test.
    while True:
        connector_id = uuid.uuid4()
        if connector_id.int % 60 >= 30:
            return connector_id


async def _stop_during_fetch() -> tuple[int, bool, int]:
    from app.connectors import CONNECTOR_REGISTRY
    from app.ingest_client import IngestClient
    from app.scheduler import ConnectorScheduler
    from app.security.credential_vault import get_vault
    from sqlalchemy.ext.asyncio import create_async_engine

    vendor = _gated_vendor()
    vendor.fetches = []
    vendor.in_flight = 0
    vendor.max_in_flight = 0
    vendor.hold = asyncio.Event()
    vendor.entered = asyncio.Event()
    CONNECTOR_REGISTRY["stub_vendor"] = vendor
    os.environ["AISOC_SCHEDULER_LEADER_ELECTION"] = "false"

    server, url = _ingest_url()
    engine = create_async_engine(_dsn())
    connector_id = _connector_id()
    first = ConnectorScheduler(engine=engine, ingest_client=IngestClient(url), vault=get_vault())
    second = ConnectorScheduler(engine=engine, ingest_client=IngestClient(url), vault=get_vault())
    try:
        await _seed(engine, connector_id)
        await first.start()
        await second.start()
        first_poll = asyncio.create_task(first._poll_one(connector_id=connector_id))
        await asyncio.wait_for(vendor.entered.wait(), 10)
        await first.stop()
        still_in_fetch = not first_poll.done()
        vendor.entered.clear()
        second_poll = asyncio.create_task(second._poll_one(connector_id=connector_id))
        try:
            await asyncio.wait_for(vendor.entered.wait(), 2)
            second_entered = True
        except TimeoutError:
            second_entered = False
        vendor.hold.set()
        await asyncio.gather(first_poll, second_poll)
        before = len(vendor.fetches)
        await second._poll_one(connector_id=connector_id)
        return vendor.max_in_flight if still_in_fetch else -1, second_entered, len(vendor.fetches) - before
    finally:
        if vendor.hold is not None:
            vendor.hold.set()
        await first.stop()
        await second.stop()
        await _drop(engine, connector_id)
        await engine.dispose()
        server.shutdown()
        CONNECTOR_REGISTRY.pop("stub_vendor", None)


def test_a_stop_during_fetch_does_not_overlap_the_other_replica() -> None:
    """The other replica stays out of a fetch that is still running.

    After that fetch returns, the same replica must fetch once. A stop
    that kept the row for the whole window would pass the overlap check
    by blocking the survivor.
    """
    max_in_flight, second_entered, after_release = asyncio.run(_stop_during_fetch())
    assert max_in_flight == 1, max_in_flight
    assert second_entered is False, second_entered
    assert after_release == 1, after_release


async def _lease_is_live(engine: Any, connector_id: uuid.UUID) -> bool:
    from sqlalchemy import text

    async with engine.connect() as conn:
        row = (
            await conn.execute(
                text("SELECT expires_at > now() FROM scheduler_leases WHERE scope = :s"),
                {"s": f"connector-poll:{connector_id}"},
            )
        ).first()
    return bool(row is not None and row[0])


async def _blocked_before_claim() -> tuple[int, int, bool, int]:
    from app.connectors import CONNECTOR_REGISTRY
    from app.ingest_client import IngestClient
    from app.scheduler import ConnectorScheduler
    from app.security.credential_vault import get_vault
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    vendor = _gated_vendor()
    vendor.fetches = []
    vendor.hold = None
    vendor.entered = None
    CONNECTOR_REGISTRY["stub_vendor"] = vendor
    os.environ["AISOC_SCHEDULER_LEADER_ELECTION"] = "false"

    server, url = _ingest_url()
    engine = create_async_engine(_dsn())
    locker = create_async_engine(_dsn())
    connector_id = _connector_id()
    running = ConnectorScheduler(engine=engine, ingest_client=IngestClient(url), vault=get_vault())
    stopped = ConnectorScheduler(engine=engine, ingest_client=IngestClient(url), vault=get_vault())
    survivor = ConnectorScheduler(engine=engine, ingest_client=IngestClient(url), vault=get_vault())
    try:
        await _seed(engine, connector_id)
        await running.start()
        lock_conn = await locker.connect()
        lock_tx = await lock_conn.begin()
        await lock_conn.execute(text("LOCK TABLE connectors IN ACCESS EXCLUSIVE MODE"))
        control_poll = asyncio.create_task(running._poll_one(connector_id=connector_id))
        await asyncio.sleep(1.0)
        control_blocked = not control_poll.done() and len(vendor.fetches) == 0
        await lock_tx.rollback()
        await lock_conn.close()
        await asyncio.wait_for(control_poll, 10)
        control_fetches = len(vendor.fetches) if control_blocked else -1
        await running.stop()

        await stopped.start()
        await survivor.start()
        lock_conn = await locker.connect()
        lock_tx = await lock_conn.begin()
        await lock_conn.execute(text("LOCK TABLE connectors IN ACCESS EXCLUSIVE MODE"))
        stopped_poll = asyncio.create_task(stopped._poll_one(connector_id=connector_id))
        await asyncio.sleep(1.0)
        await stopped.stop()
        await lock_tx.rollback()
        await lock_conn.close()
        await asyncio.wait_for(stopped_poll, 10)
        stopped_fetches = len(vendor.fetches) - control_fetches
        lease_live = await _lease_is_live(engine, connector_id)
        before = len(vendor.fetches)
        await survivor._poll_one(connector_id=connector_id)
        return control_fetches, stopped_fetches, lease_live, len(vendor.fetches) - before
    finally:
        await running.stop()
        await stopped.stop()
        await survivor.stop()
        await _drop(engine, connector_id)
        await engine.dispose()
        await locker.dispose()
        server.shutdown()
        CONNECTOR_REGISTRY.pop("stub_vendor", None)


def test_a_poll_blocked_before_the_claim_does_not_fetch_after_stop() -> None:
    """A poll that has not claimed yet must not claim after stop.

    The same poll fetches once the table lock clears while its scheduler
    is still running. A claim that refused every poll would pass the
    stopped case for the wrong reason.
    """
    control_fetches, stopped_fetches, lease_live, survivor_fetches = asyncio.run(_blocked_before_claim())
    assert control_fetches == 1, control_fetches
    assert stopped_fetches == 0, stopped_fetches
    assert lease_live is False, lease_live
    assert survivor_fetches == 1, survivor_fetches
