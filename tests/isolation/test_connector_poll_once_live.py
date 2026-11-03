from __future__ import annotations

import asyncio
import base64
import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
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
        # stop() waits until this fetch releases its lease. Waiting here
        # would sit on the hold gate below.
        stop_task = asyncio.create_task(first.stop())
        await asyncio.sleep(0.05)
        still_in_fetch = not first_poll.done()
        vendor.entered.clear()
        second_poll = asyncio.create_task(second._poll_one(connector_id=connector_id))
        try:
            await asyncio.wait_for(vendor.entered.wait(), 2)
            second_entered = True
        except TimeoutError:
            second_entered = False
        vendor.hold.set()
        await asyncio.wait_for(stop_task, 10)
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


async def _next_tick_while_the_holder_lease_is_live() -> tuple[int, int, int, int]:
    from app.connectors import CONNECTOR_REGISTRY
    from app.ingest_client import IngestClient
    from app.scheduler import ConnectorScheduler
    from app.security.credential_vault import get_vault
    from sqlalchemy.ext.asyncio import create_async_engine

    vendor = _stub_vendor()
    vendor.fetches = []
    CONNECTOR_REGISTRY["stub_vendor"] = vendor
    os.environ["AISOC_SCHEDULER_LEADER_ELECTION"] = "false"

    server, url = _ingest_url()
    engine = create_async_engine(_dsn())
    connector_id = _connector_id()
    holder = ConnectorScheduler(engine=engine, ingest_client=IngestClient(url), vault=get_vault())
    other = ConnectorScheduler(engine=engine, ingest_client=IngestClient(url), vault=get_vault())
    try:
        await _seed(engine, connector_id)
        await holder.start()
        await other.start()
        await holder._poll_one(connector_id=connector_id)
        first = len(vendor.fetches)
        await other._poll_one(connector_id=connector_id)
        during = len(vendor.fetches) - first
        # The next interval tick claims before expires_at. The lease was
        # stamped at the previous claim, one full interval later, and that
        # claim itself was after the tick had started.
        await holder._poll_one(connector_id=connector_id)
        again = len(vendor.fetches) - first - during
        await other._poll_one(connector_id=connector_id)
        after = len(vendor.fetches) - first - during - again
        return first, during, again, after
    finally:
        await holder.stop()
        await other.stop()
        await _drop(engine, connector_id)
        await engine.dispose()
        server.shutdown()
        CONNECTOR_REGISTRY.pop("stub_vendor", None)


def test_the_holder_polls_on_the_next_tick_while_its_lease_is_live() -> None:
    """The replica that holds the row must fetch on its next tick.

    Another replica must not. A lease that expired as soon as the poll
    returned would let that other replica fetch in the gap.
    """
    first, during, again, after = asyncio.run(_next_tick_while_the_holder_lease_is_live())
    assert first == 1, first
    assert during == 0, during
    assert again == 1, again
    assert after == 0, after


async def _remaining_seconds(engine: Any, connector_id: uuid.UUID) -> float:
    from sqlalchemy import text

    async with engine.connect() as conn:
        row = (
            await conn.execute(
                text("SELECT EXTRACT(EPOCH FROM (expires_at - clock_timestamp())) FROM scheduler_leases WHERE scope = :s"),
                {"s": f"connector-poll:{connector_id}"},
            )
        ).first()
    if row is None or row[0] is None:
        return -1.0
    return float(row[0])


async def _renew_past_the_remaining_lease() -> tuple[int, int, float, int, int, bool]:
    from app.connectors import CONNECTOR_REGISTRY
    from app.ingest_client import IngestClient
    from app.leader_lease import LeaderLease
    from app.scheduler import ConnectorScheduler
    from app.security.credential_vault import get_vault
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    vendor = _stub_vendor()
    vendor.fetches = []
    CONNECTOR_REGISTRY["stub_vendor"] = vendor
    os.environ["AISOC_SCHEDULER_LEADER_ELECTION"] = "false"

    server, url = _ingest_url()
    engine = create_async_engine(_dsn())
    connector_id = _connector_id()
    holder = ConnectorScheduler(engine=engine, ingest_client=IngestClient(url), vault=get_vault())
    other = ConnectorScheduler(engine=engine, ingest_client=IngestClient(url), vault=get_vault())
    scope = f"connector-poll:{connector_id}"
    original_acquire = LeaderLease.acquire
    late: asyncio.Task[None] | None = None
    lock = None
    try:
        await _seed(engine, connector_id)
        await holder.start()
        await other.start()
        await holder._poll_one(connector_id=connector_id)
        await other._poll_one(connector_id=connector_id)
        during = len(vendor.fetches)
        await holder._poll_one(connector_id=connector_id)
        valid = len(vendor.fetches) - during
        remaining = await _remaining_seconds(engine, connector_id)
        async with engine.begin() as conn:
            await conn.execute(
                text("UPDATE scheduler_leases SET expires_at = clock_timestamp() + interval '4 seconds' WHERE scope = :s"),
                {"s": scope},
            )
        lock = await engine.connect()
        await lock.begin()
        await lock.execute(
            text("UPDATE scheduler_leases SET renewed_at = renewed_at WHERE scope = :s"),
            {"s": scope},
        )

        async def _acquire_loses(self: LeaderLease) -> bool:
            del self
            return False

        # acquire() takes the same row lock. Losing without a statement lets
        # the wait sit inside renew(), which is what authorizes the fetch.
        LeaderLease.acquire = _acquire_loses  # type: ignore[method-assign]
        late = asyncio.create_task(holder._poll_one(connector_id=connector_id))
        await asyncio.sleep(1.0)
        renew_blocked = not late.done()
        await asyncio.sleep(4.0)
        await lock.commit()
        await late
        late = None
        late_fetches = len(vendor.fetches) - during - valid
        before = len(vendor.fetches)
        await other._poll_one(connector_id=connector_id)
        return valid, during, remaining, late_fetches, len(vendor.fetches) - before, renew_blocked
    finally:
        LeaderLease.acquire = original_acquire  # type: ignore[method-assign]
        if lock is not None:
            await lock.close()
        if late is not None and not late.done():
            late.cancel()
        await holder.stop()
        await other.stop()
        await _drop(engine, connector_id)
        await engine.dispose()
        server.shutdown()
        CONNECTOR_REGISTRY.pop("stub_vendor", None)


def test_a_renew_that_waits_out_the_remaining_lease_does_not_fetch() -> None:
    """A lock wait uses transaction-start now().

    When the wait outlasts the time left on the row, this replica must not
    fetch and the other replica must not take the row. A renew of a lease
    that is still valid must still fetch, and must not shorten that lease.
    """
    valid, during, remaining, late_fetches, other_after, renew_blocked = asyncio.run(_renew_past_the_remaining_lease())
    assert renew_blocked is True, renew_blocked
    assert valid == 1, valid
    assert during == 1, during
    assert remaining >= 200.0, remaining
    assert late_fetches == 0, late_fetches
    assert other_after == 0, other_after


class _ClosedEngine:
    """A process engine the lifespan has finished with. Writes must fail."""

    def begin(self) -> None:
        raise RuntimeError("engine disposed")


def _close_process_engine(scheduler: Any) -> None:
    closed = _ClosedEngine()
    scheduler._engine = closed
    for lease in scheduler._connector_leases.values():
        lease._engine = closed


async def _in_flight_release_after_stop() -> tuple[int, int, int, int]:
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
    holder_engine = create_async_engine(_dsn())
    survivor_engine = create_async_engine(_dsn())
    connector_id = _connector_id()
    holder = ConnectorScheduler(engine=holder_engine, ingest_client=IngestClient(url), vault=get_vault())
    survivor = ConnectorScheduler(engine=survivor_engine, ingest_client=IngestClient(url), vault=get_vault())
    poll: asyncio.Task[None] | None = None
    shutdown: asyncio.Task[None] | None = None
    try:
        await _seed(holder_engine, connector_id)
        await holder.start()
        await survivor.start()
        poll = asyncio.create_task(holder._poll_one(connector_id=connector_id))
        await asyncio.wait_for(vendor.entered.wait(), 10)

        async def _lifespan_shutdown() -> None:
            await holder.stop()
            # dispose() installs a fresh pool, so a later begin() still
            # writes. The lifespan has finished with this engine: close it.
            await holder_engine.dispose()
            _close_process_engine(holder)

        shutdown = asyncio.create_task(_lifespan_shutdown())
        await asyncio.wait({shutdown}, timeout=1.0)
        await survivor._poll_one(connector_id=connector_id)
        while_fetch_runs = len(vendor.fetches) - 1
        vendor.hold.set()
        try:
            await asyncio.wait_for(poll, 10)
        except Exception:
            pass
        await asyncio.wait_for(shutdown, 10)
        before = len(vendor.fetches)
        await survivor._poll_one(connector_id=connector_id)
        return while_fetch_runs, len(vendor.fetches) - before, vendor.max_in_flight, before
    finally:
        if vendor.hold is not None:
            vendor.hold.set()
        for task in (poll, shutdown):
            if task is not None and not task.done():
                try:
                    await asyncio.wait_for(task, 10)
                except Exception:
                    pass
        await survivor.stop()
        await holder.stop()
        await _drop(survivor_engine, connector_id)
        await survivor_engine.dispose()
        server.shutdown()
        CONNECTOR_REGISTRY.pop("stub_vendor", None)


def test_an_in_flight_lease_is_released_before_the_engine_closes() -> None:
    """The lifespan disposes the engine as soon as stop() returns.

    A release that runs after that cannot write, and the other replica
    waits out the poll window. Releasing at the start of stop() would let
    that replica fetch while this one is still inside fetch_alerts.
    """
    while_fetch_runs, after_stop, max_in_flight, fetches_before_survivor = asyncio.run(_in_flight_release_after_stop())
    assert while_fetch_runs == 0, while_fetch_runs
    assert max_in_flight == 1, max_in_flight
    assert fetches_before_survivor == 1, fetches_before_survivor
    assert after_stop == 1, after_stop


def _termination_grace_seconds() -> float:
    chart = Path(__file__).resolve().parents[2] / "infra/helm/aisoc/templates/deployment.yaml"
    for line in chart.read_text().splitlines():
        stripped = line.strip()
        if stripped.startswith("terminationGracePeriodSeconds:"):
            return float(stripped.split(":", 1)[1].split("#", 1)[0].strip())
    raise AssertionError("terminationGracePeriodSeconds is missing from the chart")


async def _scheduler_leases_lock_waiting(engine: Any) -> bool:
    from sqlalchemy import text

    async with engine.connect() as conn:
        waiting = (
            await conn.execute(text("SELECT COUNT(*) FROM pg_locks WHERE relation = 'scheduler_leases'::regclass AND NOT granted"))
        ).scalar_one()
        # A row lock blocks the release UPDATE on the holder's transaction id.
        # That wait does not show up as an ungranted relation lock.
        updating = (
            await conn.execute(
                text("SELECT COUNT(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE '%UPDATE scheduler_leases%'")
            )
        ).scalar_one()
    return int(waiting) > 0 or int(updating) > 0


async def _seed_another(engine: Any, existing: uuid.UUID, connector_id: uuid.UUID, name: str) -> None:
    from sqlalchemy import text

    async with engine.begin() as conn:
        tenant_id = (await conn.execute(text("SELECT tenant_id FROM connectors WHERE id = :i"), {"i": existing})).scalar_one()
        await conn.execute(
            text(
                "INSERT INTO connectors "
                "(id, tenant_id, connector_type, name, is_enabled, auth_config, connector_config) "
                "VALUES (:i, :t, 'stub_vendor', :n, true, '{}'::jsonb, CAST(:c AS jsonb))"
            ),
            {
                "i": connector_id,
                "t": tenant_id,
                "n": name,
                "c": json.dumps({"poll_interval_seconds": 300}),
            },
        )


def _queued_vendor():
    from app.connectors.base import BaseConnector, ConnectorSchema

    class QueuedVendor(BaseConnector):
        connector_id = "stub_vendor"
        connector_name = "Stub vendor"
        connector_category = "siem"
        fetches: list[str] = []
        in_flight = 0
        max_in_flight = 0
        gates: list[tuple[asyncio.Event, asyncio.Event]] = []

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
            entered = asyncio.Event()
            hold = asyncio.Event()
            vendor = type(self)
            vendor.gates.append((entered, hold))
            vendor.fetches.append("fetch")
            vendor.in_flight += 1
            vendor.max_in_flight = max(vendor.max_in_flight, vendor.in_flight)
            try:
                entered.set()
                await hold.wait()
            finally:
                vendor.in_flight -= 1
            return [{"id": "evt-1", "message": "one"}]

    return QueuedVendor


async def _stop_during_lease_claim() -> tuple[int, bool, bool, int, int, int]:
    from app.connectors import CONNECTOR_REGISTRY
    from app.ingest_client import IngestClient
    from app.scheduler import ConnectorScheduler
    from app.security.credential_vault import get_vault
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    vendor = _gated_vendor()
    vendor.fetches = []
    vendor.in_flight = 0
    vendor.max_in_flight = 0
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
    stopped_poll: asyncio.Task[None] | None = None
    stop_task: asyncio.Task[None] | None = None
    lock_conn = None
    try:
        await _seed(engine, connector_id)
        await running.start()
        lock_conn = await locker.connect()
        lock_tx = await lock_conn.begin()
        await lock_conn.execute(text("LOCK TABLE scheduler_leases IN ACCESS EXCLUSIVE MODE"))
        control_poll = asyncio.create_task(running._poll_one(connector_id=connector_id))
        control_blocked = False
        for _ in range(30):
            if control_poll.done():
                break
            if await _scheduler_leases_lock_waiting(engine):
                control_blocked = True
                break
            await asyncio.sleep(0.1)
        await lock_tx.rollback()
        await lock_conn.close()
        lock_conn = None
        await asyncio.wait_for(control_poll, 10)
        control_fetches = len(vendor.fetches) if control_blocked else -1
        await running.stop()

        await stopped.start()
        await survivor.start()
        lock_conn = await locker.connect()
        lock_tx = await lock_conn.begin()
        await lock_conn.execute(text("LOCK TABLE scheduler_leases IN ACCESS EXCLUSIVE MODE"))
        stopped_poll = asyncio.create_task(stopped._poll_one(connector_id=connector_id))
        claim_blocked = False
        for _ in range(30):
            if stopped_poll.done():
                break
            if await _scheduler_leases_lock_waiting(engine):
                claim_blocked = True
                break
            await asyncio.sleep(0.1)
        stop_task = asyncio.create_task(stopped.stop())
        await asyncio.sleep(0.5)
        # On a scheduler that clears the idle event only after the claim
        # returns, stop() is already done while this lock is still held.
        stop_waited = not stop_task.done()
        await lock_tx.rollback()
        await lock_conn.close()
        lock_conn = None
        await asyncio.wait_for(stopped_poll, 10)
        if not stop_task.done():
            await asyncio.wait_for(stop_task, 10)
        stopped_fetches = len(vendor.fetches) - control_fetches
        before = len(vendor.fetches)
        await survivor._poll_one(connector_id=connector_id)
        return (
            control_fetches,
            claim_blocked,
            stop_waited,
            stopped_fetches,
            len(vendor.fetches) - before,
            vendor.max_in_flight,
        )
    finally:
        if lock_conn is not None:
            await lock_conn.close()
        for task in (stopped_poll, stop_task):
            if task is not None and not task.done():
                task.cancel()
        await running.stop()
        await stopped.stop()
        await survivor.stop()
        await _drop(engine, connector_id)
        await engine.dispose()
        await locker.dispose()
        server.shutdown()
        CONNECTOR_REGISTRY.pop("stub_vendor", None)


def test_a_stop_during_the_lease_claim_does_not_fetch() -> None:
    """A stop that lands while the claim is blocked on the lease row must not fetch.

    The same claim fetches once when the lock clears and the scheduler is
    still running. After stop, the survivor fetches once and the two do
    not overlap.
    """
    control_fetches, claim_blocked, stop_waited, stopped_fetches, survivor_fetches, max_in_flight = asyncio.run(_stop_during_lease_claim())
    assert control_fetches == 1, control_fetches
    assert claim_blocked is True, claim_blocked
    assert (stop_waited, stopped_fetches) == (True, 0), (stop_waited, stopped_fetches)
    assert survivor_fetches == 1, survivor_fetches
    assert max_in_flight == 1, max_in_flight


async def _hung_fetch_does_not_hold_shutdown() -> tuple[float, float, float, bool, int, int, float]:
    import app.scheduler as scheduler_mod
    from app.connectors import CONNECTOR_REGISTRY
    from app.ingest_client import IngestClient
    from app.scheduler import ConnectorScheduler
    from app.security.credential_vault import get_vault
    from sqlalchemy.ext.asyncio import create_async_engine

    grace = _termination_grace_seconds()
    configured = getattr(scheduler_mod, "_STOP_IN_FLIGHT_WAIT_S", None)
    if not isinstance(configured, (int, float)) or not (0 < float(configured) < grace):
        raise AssertionError(f"stop() waits for in-flight fetches with no bound below the {grace:g}s termination grace")
    real_bound = float(configured)
    # The chart bound is what shutdown uses. Turn it down for the wait
    # itself so this suite does not sit for the whole production value.
    # stop() has to read the constant: a fixed sleep would not notice.
    exercised = min(real_bound, 2.0)

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
    holder = ConnectorScheduler(engine=engine, ingest_client=IngestClient(url), vault=get_vault())
    survivor = ConnectorScheduler(engine=engine, ingest_client=IngestClient(url), vault=get_vault())
    poll: asyncio.Task[None] | None = None
    stop_task: asyncio.Task[None] | None = None
    scheduler_mod._STOP_IN_FLIGHT_WAIT_S = exercised
    try:
        await _seed(engine, connector_id)
        await holder.start()
        await survivor.start()
        poll = asyncio.create_task(holder._poll_one(connector_id=connector_id))
        await asyncio.wait_for(vendor.entered.wait(), 10)
        started = time.monotonic()
        stop_task = asyncio.create_task(holder.stop())
        try:
            await asyncio.wait_for(stop_task, exercised + 5)
        except TimeoutError:
            elapsed = time.monotonic() - started
            raise AssertionError(f"stop() still waiting after {elapsed:.1f}s; the bound is {exercised:g}s") from None
        elapsed = time.monotonic() - started
        lease_live = await _lease_is_live(engine, connector_id)
        before = len(vendor.fetches)
        await survivor._poll_one(connector_id=connector_id)
        return (
            elapsed,
            real_bound,
            grace,
            lease_live,
            len(vendor.fetches) - before,
            vendor.max_in_flight,
            exercised,
        )
    finally:
        if vendor.hold is not None:
            vendor.hold.set()
        if poll is not None and not poll.done():
            try:
                await asyncio.wait_for(poll, 10)
            except Exception:
                poll.cancel()
        if stop_task is not None and not stop_task.done():
            stop_task.cancel()
        await survivor.stop()
        await holder.stop()
        scheduler_mod._STOP_IN_FLIGHT_WAIT_S = real_bound
        await _drop(engine, connector_id)
        await engine.dispose()
        server.shutdown()
        CONNECTOR_REGISTRY.pop("stub_vendor", None)


def test_a_hung_fetch_does_not_hold_shutdown() -> None:
    """A fetch that never returns must not pin stop() until the pod is killed.

    The wait is shorter than terminationGracePeriodSeconds. When it runs
    out the lease stays in place, so the other replica does not fetch
    while this one is still inside fetch_alerts.
    """
    elapsed, configured, grace, lease_live, survivor_fetches, max_in_flight, exercised = asyncio.run(_hung_fetch_does_not_hold_shutdown())
    assert 5 <= configured < grace, (configured, grace)
    assert exercised - 1 <= elapsed < exercised + 5, (elapsed, exercised)
    assert lease_live is True, lease_live
    assert survivor_fetches == 0, survivor_fetches
    assert max_in_flight == 1, max_in_flight


async def _stop_returns_only_after_every_release() -> tuple[bool, bool]:
    from app.connectors import CONNECTOR_REGISTRY
    from app.ingest_client import IngestClient
    from app.scheduler import ConnectorScheduler
    from app.security.credential_vault import get_vault
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine

    vendor = _queued_vendor()
    vendor.fetches = []
    vendor.in_flight = 0
    vendor.max_in_flight = 0
    vendor.gates = []
    CONNECTOR_REGISTRY["stub_vendor"] = vendor
    os.environ["AISOC_SCHEDULER_LEADER_ELECTION"] = "false"

    server, url = _ingest_url()
    engine = create_async_engine(_dsn())
    first_id = _connector_id()
    second_id = _connector_id()
    holder = ConnectorScheduler(engine=engine, ingest_client=IngestClient(url), vault=get_vault())
    polls: list[asyncio.Task[None]] = []
    stop_task: asyncio.Task[tuple[bool, bool]] | None = None
    lock_conn = None
    try:
        await _seed(engine, first_id)
        await _seed_another(engine, first_id, second_id, "stub-b")
        await holder.start()
        polls.append(asyncio.create_task(holder._poll_one(connector_id=first_id)))
        for _ in range(100):
            if vendor.gates:
                break
            await asyncio.sleep(0.05)
        else:
            raise AssertionError("the first fetch did not start")
        await asyncio.wait_for(vendor.gates[0][0].wait(), 10)
        polls.append(asyncio.create_task(holder._poll_one(connector_id=second_id)))
        for _ in range(100):
            if len(vendor.gates) > 1:
                break
            await asyncio.sleep(0.05)
        else:
            raise AssertionError("the second fetch did not start")
        await asyncio.wait_for(vendor.gates[1][0].wait(), 10)

        async def _stop_and_read() -> tuple[bool, bool]:
            await holder.stop()
            return await _lease_is_live(engine, first_id), await _lease_is_live(engine, second_id)

        stop_task = asyncio.create_task(_stop_and_read())
        await asyncio.sleep(0.3)
        if stop_task.done():
            raise AssertionError("stop() returned while both fetches were still inside fetch_alerts")

        lock_conn = await engine.connect()
        lock_tx = await lock_conn.begin()
        await lock_conn.execute(
            text("SELECT expires_at FROM scheduler_leases WHERE scope = :s FOR UPDATE"),
            {"s": f"connector-poll:{first_id}"},
        )
        vendor.gates[0][1].set()
        release_blocked = False
        for _ in range(100):
            if await _scheduler_leases_lock_waiting(engine):
                release_blocked = True
                break
            await asyncio.sleep(0.05)
        if not release_blocked:
            raise AssertionError("the first release did not block on its lease row")
        vendor.gates[1][1].set()
        for _ in range(100):
            if stop_task.done() or not await _lease_is_live(engine, second_id):
                break
            await asyncio.sleep(0.05)
        for _ in range(40):
            if stop_task.done():
                break
            await asyncio.sleep(0.05)
        if not stop_task.done():
            await lock_tx.commit()
            await lock_conn.close()
            lock_conn = None
        return await asyncio.wait_for(stop_task, 15)
    finally:
        for gate in vendor.gates:
            gate[1].set()
        if lock_conn is not None:
            await lock_conn.close()
        for task in polls:
            if not task.done():
                task.cancel()
        if stop_task is not None and not stop_task.done():
            stop_task.cancel()
        await holder.stop()
        await _drop(engine, first_id)
        await _drop(engine, second_id)
        await engine.dispose()
        server.shutdown()
        CONNECTOR_REGISTRY.pop("stub_vendor", None)


def test_a_stop_returns_only_after_every_in_flight_release() -> None:
    """Two fetches finishing during stop() must both release before stop() returns.

    One task can see an empty in-flight set and wake the waiter while the
    other task is still inside its release. The lease row, not the idle
    event, is what the next replica reads.
    """
    first_live, second_live = asyncio.run(_stop_returns_only_after_every_release())
    assert (first_live, second_live) == (False, False), (first_live, second_live)
