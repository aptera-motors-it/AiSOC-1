from __future__ import annotations

import asyncio
import os
import sys
import time
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import urlparse

import pytest
import pytest_asyncio
from redis.asyncio import from_url

URL = os.getenv("AISOC_TEST_REDIS", "").strip()
pytestmark = pytest.mark.skipif(not URL, reason="set AISOC_TEST_REDIS=redis://host:port/db to run the live scheduler-lock proof")

TTL_SECONDS = 3
RETRY_SECONDS = 0.5
CONTENDER_RETRY_SECONDS = 0.05
HANDOVER_SLACK_SECONDS = 0.1
API_ROOT = Path(__file__).resolve().parents[1]

REPLICA = """
import asyncio, sys, time
from app import main

async def worker():
    print("start", time.time(), flush=True)
    try:
        await asyncio.Event().wait()
    finally:
        print("stop", time.time(), flush=True)

main._SCHEDULER_LOCK_RETRY_SECONDS = float(sys.argv[3])
print("ready", flush=True)
sys.stdin.readline()
asyncio.run(main._run_guarded_scheduler_worker(job_name=sys.argv[1], ttl_seconds=int(sys.argv[2]), worker=worker))
"""


async def _pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except OSError:
        pass
    finally:
        writer.close()


class _Proxy:
    def __init__(self) -> None:
        parsed = urlparse(URL)
        self._upstream = (parsed.hostname or "127.0.0.1", parsed.port or 6379)
        self._db_path = parsed.path
        self._server: asyncio.Server | None = None
        self._writers: list[asyncio.StreamWriter] = []
        self.port = 0

    @property
    def url(self) -> str:
        return f"redis://127.0.0.1:{self.port}{self._db_path}"

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._accept, "127.0.0.1", self.port)
        self.port = self._server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        if self._server is None:
            return
        self._server.close()
        for writer in self._writers:
            writer.close()
        self._writers.clear()
        await self._server.wait_closed()
        self._server = None

    async def _accept(self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter) -> None:
        upstream_reader, upstream_writer = await asyncio.open_connection(*self._upstream)
        self._writers += [client_writer, upstream_writer]
        await asyncio.gather(_pipe(client_reader, upstream_writer), _pipe(upstream_reader, client_writer))


class _Replica:
    def __init__(self, name: str, proc: asyncio.subprocess.Process, events: list[tuple[float, str, str]]) -> None:
        self.name = name
        self.proc = proc
        self._events = events
        self._lines: list[str] = []
        self._reader = asyncio.create_task(self._read())

    async def _read(self) -> None:
        assert self.proc.stdout is not None
        while raw := await self.proc.stdout.readline():
            line, _, at = raw.decode().strip().partition(" ")
            self._lines.append(line)
            if line in ("start", "stop"):
                self._events.append((float(at), self.name, line))

    @property
    def running(self) -> bool:
        return self._lines.count("start") > self._lines.count("stop")

    async def wait_for(self, line: str) -> None:
        async with asyncio.timeout(60):
            while line not in self._lines:
                await asyncio.sleep(0.02)

    def go(self) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(b"\n")


class _Cluster:
    def __init__(self) -> None:
        self.job = f"live_{uuid.uuid4().hex[:8]}"
        self.events: list[tuple[float, str, str]] = []
        self.proxy = _Proxy()
        self.replicas: list[_Replica] = []

    async def spawn(self, name: str, redis_url: str, retry_seconds: float = RETRY_SECONDS) -> _Replica:
        proc = await asyncio.create_subprocess_exec(
            sys.executable,
            "-c",
            REPLICA,
            self.job,
            str(TTL_SECONDS),
            str(retry_seconds),
            cwd=API_ROOT,
            env={**os.environ, "REDIS_URL": redis_url},
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        self.replicas.append(_Replica(name, proc, self.events))
        return self.replicas[-1]

    def longest_overlap_seconds(self) -> float:
        running: set[str] = set()
        both_since: float | None = None
        longest = 0.0
        for at, name, line in sorted(self.events):
            if line == "start":
                running.add(name)
            else:
                running.discard(name)
            if len(running) > 1 and both_since is None:
                both_since = at
            elif len(running) < 2 and both_since is not None:
                longest = max(longest, at - both_since)
                both_since = None
        if both_since is not None:
            longest = max(longest, time.time() - both_since)
        return longest

    async def lease_ttl(self) -> int:
        redis = from_url(URL, decode_responses=True)
        try:
            return int(await redis.ttl(f"scheduler_lock:{self.job}"))
        finally:
            await redis.aclose()

    async def delete_lease_right_after_a_renewal(self) -> None:
        key = f"scheduler_lock:{self.job}"
        redis = from_url(URL, decode_responses=True)
        try:
            holder, last = await redis.pipeline().get(key).pttl(key).execute()
            assert holder is not None
            async with asyncio.timeout(TTL_SECONDS):
                while True:
                    token, pttl = await redis.pipeline().get(key).pttl(key).execute()
                    assert token == holder, "the lease changed hands before its holder renewed it"
                    if pttl > last:
                        break
                    last = pttl
                    await asyncio.sleep(0.005)
            await redis.delete(key)
        finally:
            await redis.aclose()


@pytest_asyncio.fixture
async def cluster() -> AsyncIterator[_Cluster]:
    c = _Cluster()
    yield c
    for replica in c.replicas:
        if replica.proc.returncode is None:
            replica.proc.kill()
        await replica.proc.wait()
    await c.proxy.stop()
    redis = from_url(URL, decode_responses=True)
    await redis.delete(f"scheduler_lock:{c.job}")
    await redis.aclose()


async def test_a_blip_shorter_than_the_lease_leaves_one_runner_holding_it(cluster: _Cluster) -> None:
    await cluster.proxy.start()
    r1 = await cluster.spawn("r1", cluster.proxy.url)
    r2 = await cluster.spawn("r2", URL)
    await r1.wait_for("ready")
    await r2.wait_for("ready")

    r1.go()
    await r1.wait_for("start")
    r2.go()

    await asyncio.sleep(1.5)
    await cluster.proxy.stop()
    await asyncio.sleep(1.0)
    await cluster.proxy.start()
    await asyncio.sleep(4.0)

    assert (r1.running, r2.running) == (True, False), cluster.events
    assert cluster.longest_overlap_seconds() < HANDOVER_SLACK_SECONDS, cluster.events
    assert await cluster.lease_ttl() > 0


async def test_redis_down_at_acquire_runs_nobody_until_it_returns(cluster: _Cluster) -> None:
    await cluster.proxy.start()
    await cluster.proxy.stop()
    r1 = await cluster.spawn("r1", cluster.proxy.url)
    r2 = await cluster.spawn("r2", cluster.proxy.url)
    await r1.wait_for("ready")
    await r2.wait_for("ready")

    r1.go()
    r2.go()
    await asyncio.sleep(2.0)
    assert cluster.events == []

    await cluster.proxy.start()
    await asyncio.sleep(2.0)

    assert sorted([r1.running, r2.running]) == [False, True], cluster.events
    assert cluster.longest_overlap_seconds() < HANDOVER_SLACK_SECONDS, cluster.events
    assert await cluster.lease_ttl() > 0


async def test_a_runner_cut_off_past_its_lease_stops_and_the_other_takes_over(cluster: _Cluster) -> None:
    await cluster.proxy.start()
    r1 = await cluster.spawn("r1", cluster.proxy.url)
    r2 = await cluster.spawn("r2", URL)
    await r1.wait_for("ready")
    await r2.wait_for("ready")

    r1.go()
    await r1.wait_for("start")
    r2.go()

    await asyncio.sleep(1.5)
    await cluster.proxy.stop()
    await asyncio.sleep(4.5)
    await cluster.proxy.start()
    await asyncio.sleep(2.0)

    assert (r1.running, r2.running) == (False, True), cluster.events
    assert cluster.longest_overlap_seconds() < HANDOVER_SLACK_SECONDS, cluster.events
    assert await cluster.lease_ttl() > 0


async def test_a_key_deleted_right_after_a_renewal_stops_the_holder_at_its_next_renewal(cluster: _Cluster) -> None:
    r1 = await cluster.spawn("r1", URL)
    r2 = await cluster.spawn("r2", URL, retry_seconds=CONTENDER_RETRY_SECONDS)
    await r1.wait_for("ready")
    await r2.wait_for("ready")

    r1.go()
    await r1.wait_for("start")
    r2.go()

    await cluster.delete_lease_right_after_a_renewal()
    await asyncio.sleep(2.5)

    assert (r1.running, r2.running) == (False, True), cluster.events
    assert cluster.longest_overlap_seconds() < TTL_SECONDS // 3 + HANDOVER_SLACK_SECONDS, cluster.events
    assert await cluster.lease_ttl() > 0
