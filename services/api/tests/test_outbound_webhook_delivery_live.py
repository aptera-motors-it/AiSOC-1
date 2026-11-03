"""Two delivery workers attempt one due row once."""

from __future__ import annotations

import asyncio
import os
import threading
import time
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast

import pytest
import pytest_asyncio
from app.db.database import engine as app_engine
from app.models.outbound_webhook import OutboundDelivery, OutboundWebhook
from app.workers.outbound_webhook_delivery import run_once
from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

DSN = os.environ.get("DATABASE_URL", "")
OWNER_DSN = os.environ.get("DATABASE_MIGRATION_URL", "") or DSN
REQUIRED = os.environ.get("MSSP_ISOLATION_REQUIRED", "").strip() not in ("", "0", "false")

PRIOR_ATTEMPTS = 2

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
        server = cast(_HoldingServer, self.server)
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


def _overlap_observed(posts: int, finished: int) -> bool:
    return posts >= 2 or (finished > 0 and posts >= 1)


async def _wait_for_race(server: _HoldingServer, tasks: list[asyncio.Task[dict[str, int]]]) -> int:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with server.lock:
            posts = len(server.bodies)
        finished = len([task for task in tasks if task.done()])
        if _overlap_observed(posts, finished):
            return posts
        await asyncio.sleep(0.01)
    with server.lock:
        return len(server.bodies)


@pytest.mark.asyncio
async def test_two_workers_attempt_a_due_row_once(owner, monkeypatch: pytest.MonkeyPatch) -> None:
    tenant_id = uuid.uuid4()
    webhook_id = uuid.uuid4()
    delivery_id = uuid.uuid4()
    server, thread = _start_server()
    bound_host = server.server_address[0]
    host = bound_host.decode() if isinstance(bound_host, bytes) else bound_host
    port = server.server_address[1]
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
            payload={"n": PRIOR_ATTEMPTS},
            status="pending",
            attempts=PRIOR_ATTEMPTS,
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
        tallies = [result for result in finished if isinstance(result, dict)]
        assert not errors, errors
        assert sum(result["attempted"] for result in tallies) == 1
        assert row.attempts == PRIOR_ATTEMPTS + 1
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
        await app_engine.dispose()


class _ReplyServer(ThreadingHTTPServer):
    def __init__(self, status_code: int, body: bytes, content_type: str = "text/plain") -> None:
        super().__init__(("127.0.0.1", 0), _Reply)
        self.status_code = status_code
        self.body = body
        self.content_type = content_type
        self.count = 0
        self.lock = threading.Lock()


class _Reply(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        server = cast(_ReplyServer, self.server)
        with server.lock:
            server.count += 1
        payload = server.body
        self.send_response(server.status_code)
        self.send_header("Content-Type", server.content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def _serve(status_code: int, body: bytes, content_type: str = "text/plain") -> tuple[_ReplyServer, threading.Thread]:
    server = _ReplyServer(status_code, body, content_type)
    thread = threading.Thread(target=server.serve_forever, name="webhook-reply", daemon=True)
    thread.start()
    return server, thread


async def _seed_due(owner, *, url: str, attempts: int, age_s: int) -> tuple[uuid.UUID, uuid.UUID]:
    tenant_id = uuid.uuid4()
    webhook_id = uuid.uuid4()
    delivery_id = uuid.uuid4()
    await owner.execute(
        text("INSERT INTO tenants (id, name, slug) VALUES (:id, :name, :slug)"),
        {"id": tenant_id, "name": "Webhook claim", "slug": f"wh-{tenant_id.hex[:12]}"},
    )
    owner.add(
        OutboundWebhook(
            id=webhook_id,
            tenant_id=tenant_id,
            name="siem",
            url=url,
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
            payload={},
            status="pending",
            attempts=attempts,
            next_attempt_at=datetime.now(UTC) - timedelta(seconds=age_s),
        )
    )
    await owner.commit()
    return tenant_id, delivery_id


async def _delete_tenant(owner, tenant_id: uuid.UUID) -> None:
    await owner.rollback()
    await owner.execute(text("DELETE FROM aisoc_outbound_deliveries WHERE tenant_id = :id"), {"id": tenant_id})
    await owner.execute(text("DELETE FROM aisoc_outbound_webhooks WHERE tenant_id = :id"), {"id": tenant_id})
    await owner.execute(text("DELETE FROM tenants WHERE id = :id"), {"id": tenant_id})
    await owner.commit()


@pytest.mark.asyncio
async def test_a_nul_error_body_is_recorded_and_the_next_row_is_sent(owner, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_SSRF_ALLOW_HOSTS", "127.0.0.1")
    for name in _PROXY_VARS:
        monkeypatch.delenv(name, raising=False)
    bad, bad_thread = _serve(500, b"upstream\x00error")
    good, good_thread = _serve(200, b"ok")
    bad_host, bad_port = bad.server_address[0], bad.server_address[1]
    good_host, good_port = good.server_address[0], good.server_address[1]
    bad_url_host = bad_host.decode() if isinstance(bad_host, bytes) else bad_host
    good_url_host = good_host.decode() if isinstance(good_host, bytes) else good_host
    poisoned_tenant, poisoned_id = await _seed_due(owner, url=f"http://{bad_url_host}:{bad_port}/bad", attempts=PRIOR_ATTEMPTS, age_s=10)
    healthy_tenant, healthy_id = await _seed_due(owner, url=f"http://{good_url_host}:{good_port}/good", attempts=PRIOR_ATTEMPTS, age_s=5)
    try:
        tally = await run_once()
        poisoned = (
            await owner.execute(
                text("SELECT attempts, status, last_error FROM aisoc_outbound_deliveries WHERE id = :id"),
                {"id": poisoned_id},
            )
        ).one()
        healthy = (
            await owner.execute(
                text("SELECT attempts, status FROM aisoc_outbound_deliveries WHERE id = :id"),
                {"id": healthy_id},
            )
        ).one()
        assert tally["attempted"] == 2
        assert poisoned.attempts == PRIOR_ATTEMPTS + 1
        assert poisoned.status == "pending"
        assert "\x00" not in poisoned.last_error
        assert healthy.attempts == PRIOR_ATTEMPTS + 1
        assert healthy.status == "delivered"
        assert bad.count == 1
        assert good.count == 1
    finally:
        bad.shutdown()
        good.shutdown()
        bad_thread.join(timeout=2)
        good_thread.join(timeout=2)
        await _delete_tenant(owner, poisoned_tenant)
        await _delete_tenant(owner, healthy_tenant)
        await app_engine.dispose()


def _host(server: _ReplyServer) -> str:
    bound = server.server_address[0]
    if isinstance(bound, str):
        return bound
    return bound.decode()


@pytest.mark.asyncio
async def test_an_undecodable_error_body_is_recorded_and_the_next_row_is_sent(owner, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AISOC_SSRF_ALLOW_HOSTS", "127.0.0.1")
    for name in _PROXY_VARS:
        monkeypatch.delenv(name, raising=False)
    surrogate, surrogate_thread = _serve(500, b"upstream +2AA- error", "text/plain; charset=utf-7")
    odd, odd_thread = _serve(500, b"upstream error", "text/plain; charset=hex")
    good, good_thread = _serve(200, b"ok")
    surrogate_tenant, surrogate_id = await _seed_due(
        owner, url=f"http://{_host(surrogate)}:{surrogate.server_address[1]}/bad", attempts=PRIOR_ATTEMPTS, age_s=10
    )
    odd_tenant, odd_id = await _seed_due(owner, url=f"http://{_host(odd)}:{odd.server_address[1]}/odd", attempts=PRIOR_ATTEMPTS, age_s=8)
    healthy_tenant, healthy_id = await _seed_due(
        owner, url=f"http://{_host(good)}:{good.server_address[1]}/good", attempts=PRIOR_ATTEMPTS, age_s=5
    )
    try:
        tally = await run_once()
        again = await run_once()
        rows = (
            await owner.execute(
                text("SELECT id, attempts, status, last_error FROM aisoc_outbound_deliveries WHERE id IN (:a, :b, :c)"),
                {"a": surrogate_id, "b": odd_id, "c": healthy_id},
            )
        ).all()
        by_id = {row.id: row for row in rows}
        assert tally["attempted"] == 3
        assert again["attempted"] == 0
        for delivery_id in (surrogate_id, odd_id):
            row = by_id[delivery_id]
            assert row.attempts == PRIOR_ATTEMPTS + 1
            assert row.status == "pending"
            assert row.last_error
            assert "\x00" not in row.last_error
            assert "\ud800" not in row.last_error
        healthy = by_id[healthy_id]
        assert healthy.attempts == PRIOR_ATTEMPTS + 1
        assert healthy.status == "delivered"
        assert surrogate.count == 1
        assert odd.count == 1
        assert good.count == 1
    finally:
        for server, thread in ((surrogate, surrogate_thread), (odd, odd_thread), (good, good_thread)):
            server.shutdown()
            thread.join(timeout=2)
        await _delete_tenant(owner, surrogate_tenant)
        await _delete_tenant(owner, odd_tenant)
        await _delete_tenant(owner, healthy_tenant)
        await app_engine.dispose()
