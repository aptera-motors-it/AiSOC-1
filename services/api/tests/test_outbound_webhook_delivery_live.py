"""Two delivery workers attempt one due row once.

The sweeper reads due rows and commits after the batch. Two replicas both
see attempts = N, both POST, and both write attempts = N + 1. The column
cannot tell those two writes apart, so the receiver's request count is the
observation: one delivery, one request, attempts left at N + 1.

Live because SKIP LOCKED and the runtime role's row security are properties
of Postgres. Skips without a database rather than passing without one.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import pytest_asyncio
from app.models.outbound_webhook import OutboundDelivery, OutboundWebhook
from app.workers.outbound_webhook_delivery import run_once
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
OWNER_DSN = os.environ.get("DATABASE_MIGRATION_URL", "") or DSN
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

# A prior attempt count. Two overlapping workers must leave this at N + 1.
N = 2

_PROXY_VARS = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
)


class _HoldingServer(ThreadingHTTPServer):
    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.bodies: list[bytes] = []
        self.lock = threading.Lock()
        self.release = threading.Event()


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        server: _HoldingServer = self.server  # type: ignore[assignment]
        with server.lock:
            server.bodies.append(body)
        server.release.wait(timeout=15)
        payload = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def _postgres(dsn: str) -> bool:
    return "postgres" in dsn


@pytest_asyncio.fixture
async def owner():
    if not _postgres(DSN) and not REQUIRED:
        pytest.skip("needs a live Postgres with the migration chain applied (integration.yml)")
    if not _postgres(OWNER_DSN) and not REQUIRED:
        pytest.skip("needs DATABASE_MIGRATION_URL or DATABASE_URL for the owner role")
    engine = create_async_engine(OWNER_DSN)
    try:
        async with engine.connect() as probe:
            await probe.execute(text("SELECT 1"))
    except Exception as exc:
        await engine.dispose()
        if REQUIRED:
            pytest.fail(f"MSSP_ISOLATION_REQUIRED is set and no database answered at the owner DSN: {type(exc).__name__}: {exc}")
        pytest.skip(f"no database at the owner DSN ({type(exc).__name__}) — runs in integration.yml")

    factory = async_sessionmaker(engine, expire_on_commit=False)
    async with factory() as session:
        yield session
    await engine.dispose()


def _start_server() -> tuple[_HoldingServer, threading.Thread]:
    server = _HoldingServer()
    thread = threading.Thread(target=server.serve_forever, name="webhook-receiver", daemon=True)
    thread.start()
    return server, thread


async def _wait_for_race(server: _HoldingServer, tasks: list[asyncio.Task[dict[str, int]]]) -> int:
    """Return how many POSTs arrived once the overlap is visible.

    Two claimants both block inside the receiver. One claimant returns
    while the other is still inside it.
    """
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with server.lock:
            posts = len(server.bodies)
        finished = [task for task in tasks if task.done()]
        if posts >= 2 or (finished and posts >= 1):
            return posts
        await asyncio.sleep(0.01)
    with server.lock:
        return len(server.bodies)


@pytest.mark.asyncio
async def test_two_workers_leave_attempts_at_n_plus_one(owner, monkeypatch: pytest.MonkeyPatch) -> None:
    tenant_id = uuid.uuid4()
    webhook_id = uuid.uuid4()
    delivery_id = uuid.uuid4()
    server, thread = _start_server()
    host, port = server.server_address[:2]
    monkeypatch.setenv("AISOC_SSRF_ALLOW_HOSTS", "127.0.0.1")
    for name in _PROXY_VARS:
        monkeypatch.delenv(name, raising=False)

    await owner.execute(
        text("INSERT INTO tenants (id, name, slug) VALUES (:id, :name, :slug)"),
        {"id": tenant_id, "name": "Webhook claim", "slug": f"wh-{tenant_id.hex[:12]}"},
    )
    owner.add(
        OutboundWebhook(
            id=webhook_id,
            tenant_id=tenant_id,
            name="siem",
            url=f"http://{host}:{port}/hook",
            secret="",
            enabled=True,
        )
    )
    await owner.flush()
    owner.add(
        OutboundDelivery(
            id=delivery_id,
            tenant_id=tenant_id,
            webhook_id=webhook_id,
            event_type="alert.updated",
            payload={"n": N},
            status="pending",
            attempts=N,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=1),
        )
    )
    await owner.commit()

    tasks = [asyncio.create_task(run_once()), asyncio.create_task(run_once())]
    try:
        posts = await _wait_for_race(server, tasks)
        server.release.set()
        finished = await asyncio.gather(*tasks, return_exceptions=True)
        row = (
            await owner.execute(
                text("SELECT attempts, status FROM aisoc_outbound_deliveries WHERE id = :id"),
                {"id": delivery_id},
            )
        ).one()
        assert posts == 1, f"one due row was posted {posts} times while both workers ran"
        errors = [result for result in finished if isinstance(result, BaseException)]
        assert not errors, errors
        assert sum(result["attempted"] for result in finished) == 1
        assert row.attempts == N + 1
        assert row.status == "delivered"
        with server.lock:
            assert len(server.bodies) == 1
    finally:
        server.release.set()
        pending = [task for task in tasks if not task.done()]
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        server.shutdown()
        thread.join(timeout=2)
        await owner.execute(text("DELETE FROM aisoc_outbound_deliveries WHERE tenant_id = :id"), {"id": tenant_id})
        await owner.execute(text("DELETE FROM aisoc_outbound_webhooks WHERE tenant_id = :id"), {"id": tenant_id})
        await owner.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
        await owner.commit()
