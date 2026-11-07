"""The windowed engine's claim protocol, against a real Redis.

``tests/test_windowed_replay_safety.py`` drives the engine over an in-memory
double, which proves the *decisions*. It cannot prove the two things the
protocol actually rests on, because both are properties of the server:

* ``SET key token NX EX`` is atomic, so exactly one of two concurrent
  workers takes the claim;
* the owner check and the write inside ``_CONFIRM_IF_OWNER`` /
  ``_RELEASE_IF_OWNER`` happen together, so a worker cannot resolve a claim
  that expired and was retaken by somebody else in between.

A Python double implements both by construction — it is single-threaded —
so it would pass whether or not the scripts are correct. That is exactly
the more-capable-than-reality shape this repository keeps finding, which is
why these run against the server.

Skips cleanly when no server is reachable, and says so rather than passing
quietly.

    docker run -d --name aisoc-wd-redis -p 56379:6379 redis:7-alpine
    AISOC_TEST_REDIS=redis://127.0.0.1:56379/0 pytest tests/integration/test_windowed_detection_live.py
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from app.services.windowed_detection import (
    FIRE_CLAIM_SECONDS,
    FIRED_CONFIRMED,
    WindowedDetectionEngine,
    WindowRule,
)

URL = os.getenv("AISOC_TEST_REDIS", "").strip()
pytestmark = pytest.mark.skipif(not URL, reason="set AISOC_TEST_REDIS=redis://host:port/db to run the live claim proof")

_RULE = WindowRule(
    id="wd-bruteforce-auth",
    name="Brute-force: repeated authentication failures",
    severity="high",
    category="identity",
    mitre=["T1110"],
    match_when={"event_type": "authentication", "outcome": "failure"},
    group_by="user",
    threshold=5,
    window_seconds=600,
)


@pytest_asyncio.fixture
async def redis():  # noqa: ANN201
    aioredis = pytest.importorskip("redis.asyncio")
    client = aioredis.from_url(URL, decode_responses=True)
    await client.flushdb()
    yield client
    await client.aclose()


def _auth_fail(tenant: str, when: str, user: str = "alice") -> dict:
    return {
        "tenant_id": tenant,
        "ocsf_event": {
            "tenant_uid": tenant,
            "raw_data": json.dumps({"event_type": "authentication", "outcome": "failure", "user": user, "timestamp": when}),
        },
    }


async def _drive_to_threshold(engine, tenant, *, start=0, count=4):  # noqa: ANN001, ANN202
    hits = []
    for n in range(start, start + count):
        hits += await engine.evaluate(_auth_fail(tenant, f"2026-10-27T12:00:{n:02d}Z"), event_id=f"evt-{n}")
    return hits


@pytest.mark.asyncio
async def test_a_real_threshold_crossing_claims_exactly_once(redis):  # noqa: ANN001
    engine = WindowedDetectionEngine(redis, rules=(_RULE,))
    tenant = str(uuid.uuid4())
    assert await _drive_to_threshold(engine, tenant) == []

    hits = await engine.evaluate(_auth_fail(tenant, "2026-10-27T12:00:04Z"), event_id="evt-4")
    assert len(hits) == 1

    # The claim is a token with a short lease, not the window-long marker.
    key, token = hits[0].claim_key, hits[0].claim_token
    assert await redis.get(key) == token
    ttl = await redis.ttl(key)
    assert 0 < ttl <= FIRE_CLAIM_SECONDS, "a claim must age out well inside the window"


@pytest.mark.asyncio
async def test_two_concurrent_workers_take_one_claim_between_them(redis):  # noqa: ANN001
    """SET NX is the mutual exclusion, and only a real server settles it."""
    worker_a = WindowedDetectionEngine(redis, rules=(_RULE,))
    worker_b = WindowedDetectionEngine(redis, rules=(_RULE,))
    tenant = str(uuid.uuid4())
    await _drive_to_threshold(worker_a, tenant)

    hits_a = await worker_a.evaluate(_auth_fail(tenant, "2026-10-27T12:00:04Z"), event_id="evt-4")
    hits_b = await worker_b.evaluate(_auth_fail(tenant, "2026-10-27T12:00:05Z"), event_id="evt-5")

    assert len(hits_a) + len(hits_b) == 1


@pytest.mark.asyncio
async def test_a_crossing_re_delivered_inside_a_dead_workers_lease_still_fires(redis):  # noqa: ANN001
    """A committed threshold crossing has an alert.

    The worker that crossed the threshold died between the claim and the
    database, so nothing released the claim. Its offset never committed, so
    Kafka hands the same record to the restarted worker inside the lease. If
    that delivery finds the slot taken and returns nothing, the consumer
    commits the offset and no later delivery exists to recover the alert.
    """
    dead = WindowedDetectionEngine(redis, rules=(_RULE,))
    tenant = str(uuid.uuid4())
    await _drive_to_threshold(dead, tenant)
    crossing = _auth_fail(tenant, "2026-10-27T12:00:04Z")
    assert len(await dead.evaluate(crossing, event_id="evt-4")) == 1

    restarted = WindowedDetectionEngine(redis, rules=(_RULE,))
    hits = await restarted.evaluate(crossing, event_id="evt-4")

    assert len(hits) == 1, "a re-delivery of the crossing event must recover its hit, not commit past it"
    await restarted.confirm(hits[0])
    assert await redis.get(hits[0].claim_key) == FIRED_CONFIRMED, "the recovered hit must be able to resolve the claim"


@pytest.mark.asyncio
async def test_a_re_delivery_late_in_the_lease_still_has_time_to_confirm(redis):  # noqa: ANN001
    """The recovered hit gets a whole lease, not what the dead worker left.

    The re-delivery waits out the consumer group's session timeout, which can
    leave it near the end of the lease. Inheriting the remainder lets the
    claim expire while the alert is persisted, the confirm finds nothing to
    promote, and the window is open to a second alert.
    """
    dead = WindowedDetectionEngine(redis, rules=(_RULE,))
    tenant = str(uuid.uuid4())
    await _drive_to_threshold(dead, tenant)
    crossing = _auth_fail(tenant, "2026-10-27T12:00:04Z")
    key = (await dead.evaluate(crossing, event_id="evt-4"))[0].claim_key
    await redis.pexpire(key, 100)

    restarted = WindowedDetectionEngine(redis, rules=(_RULE,))
    hits = await restarted.evaluate(crossing, event_id="evt-4")
    assert len(hits) == 1
    await asyncio.sleep(0.2)
    await restarted.confirm(hits[0])

    assert await redis.get(key) == FIRED_CONFIRMED, "a claim resumed late in its lease must survive until its confirm"


@pytest.mark.asyncio
async def test_a_failed_re_delivery_cannot_free_a_claim_another_delivery_will_confirm(redis):  # noqa: ANN001
    """One crossing, one alert, even with two deliveries of it in flight.

    A consumer rebalance can hand the crossing record to a second worker
    while the first is still persisting. Both resume the claim. If the second
    fails and its release frees the slot, a different event claims it before
    the first confirms, and the window gets two alerts.
    """
    first = WindowedDetectionEngine(redis, rules=(_RULE,))
    second = WindowedDetectionEngine(redis, rules=(_RULE,))
    tenant = str(uuid.uuid4())
    await _drive_to_threshold(first, tenant)
    crossing = _auth_fail(tenant, "2026-10-27T12:00:04Z")
    hit = (await first.evaluate(crossing, event_id="evt-4"))[0]
    await second.release((await second.evaluate(crossing, event_id="evt-4"))[0])

    assert await second.evaluate(_auth_fail(tenant, "2026-10-27T12:00:05Z"), event_id="evt-5") == []
    await first.confirm(hit)
    assert await redis.get(hit.claim_key) == FIRED_CONFIRMED


@pytest.mark.asyncio
async def test_a_re_delivery_without_an_event_time_lands_where_the_first_did(redis, monkeypatch):  # noqa: ANN001
    """Arrival time is when ingest stamped the record, not when a worker read it.

    By the worker's clock the re-delivery arrives a minute later, its window
    slides past the oldest of the five failures, and the crossing it already
    claimed no longer counts to the threshold.
    """
    clock = [0.0]
    monkeypatch.setattr(time, "time", lambda: clock[0])
    engine = WindowedDetectionEngine(redis, rules=(_RULE,))
    tenant = str(uuid.uuid4())
    start = datetime(2026, 10, 27, 12, tzinfo=UTC)

    def arrived(n: int) -> dict:
        stamp = start + timedelta(seconds=150 * n)
        clock[0] = stamp.timestamp() + 1
        raw = {"event_type": "authentication", "outcome": "failure", "user": "alice"}
        return {"tenant_id": tenant, "ocsf_event": {"tenant_uid": tenant, "ingest_time": stamp.isoformat(), "raw_data": json.dumps(raw)}}

    hits = [len(await engine.evaluate(arrived(n), event_id=f"evt-{n}")) for n in range(5)]
    assert hits == [0, 0, 0, 0, 1]
    crossing = arrived(4)
    clock[0] += 60

    assert len(await engine.evaluate(crossing, event_id="evt-4")) == 1


@pytest.mark.asyncio
async def test_confirm_promotes_the_claim_to_the_window_cooldown(redis):  # noqa: ANN001
    engine = WindowedDetectionEngine(redis, rules=(_RULE,))
    tenant = str(uuid.uuid4())
    await _drive_to_threshold(engine, tenant)
    hit = (await engine.evaluate(_auth_fail(tenant, "2026-10-27T12:00:04Z"), event_id="evt-4"))[0]

    await engine.confirm(hit)

    assert await redis.get(hit.claim_key) == FIRED_CONFIRMED
    assert await redis.ttl(hit.claim_key) > FIRE_CLAIM_SECONDS, "a durable hit holds the slot for the window, not the lease"
    assert await engine.evaluate(_auth_fail(tenant, "2026-10-27T12:00:06Z"), event_id="evt-6") == []


@pytest.mark.asyncio
async def test_release_frees_the_slot_so_a_retry_can_fire(redis):  # noqa: ANN001
    engine = WindowedDetectionEngine(redis, rules=(_RULE,))
    tenant = str(uuid.uuid4())
    await _drive_to_threshold(engine, tenant)
    hit = (await engine.evaluate(_auth_fail(tenant, "2026-10-27T12:00:04Z"), event_id="evt-4"))[0]

    await engine.release(hit)

    assert await redis.get(hit.claim_key) is None
    again = await engine.evaluate(_auth_fail(tenant, "2026-10-27T12:00:04Z"), event_id="evt-4")
    assert len(again) == 1, "a hit that reached no database must be re-claimable"


@pytest.mark.asyncio
async def test_a_worker_cannot_release_another_workers_claim(redis):  # noqa: ANN001
    """The owner check is the whole reason these are scripts and not a DEL.

    Without it, a worker whose lease expired would delete the claim of the
    worker that took it next -- and that second worker's alert would then be
    published twice.
    """
    engine = WindowedDetectionEngine(redis, rules=(_RULE,))
    tenant = str(uuid.uuid4())
    await _drive_to_threshold(engine, tenant)
    hit = (await engine.evaluate(_auth_fail(tenant, "2026-10-27T12:00:04Z"), event_id="evt-4"))[0]

    # A second worker's claim lands on the same key after the first expired.
    await redis.set(hit.claim_key, "another-workers-token", ex=FIRE_CLAIM_SECONDS)
    await engine.release(hit)

    assert await redis.get(hit.claim_key) == "another-workers-token", "a stale worker must not free a live claim"


@pytest.mark.asyncio
async def test_a_worker_cannot_confirm_another_workers_claim(redis):  # noqa: ANN001
    """The mirror image: confirming someone else's claim would mark an alert
    durable that the other worker has not persisted yet."""
    engine = WindowedDetectionEngine(redis, rules=(_RULE,))
    tenant = str(uuid.uuid4())
    await _drive_to_threshold(engine, tenant)
    hit = (await engine.evaluate(_auth_fail(tenant, "2026-10-27T12:00:04Z"), event_id="evt-4"))[0]

    await redis.set(hit.claim_key, "another-workers-token", ex=FIRE_CLAIM_SECONDS)
    await engine.confirm(hit)

    assert await redis.get(hit.claim_key) == "another-workers-token"


@pytest.mark.asyncio
async def test_re_delivery_does_not_inflate_the_count_on_a_real_server(redis):  # noqa: ANN001
    """ZADD on an existing member updates its score instead of adding a row.

    The whole idempotence argument rests on that, so it is worth asserting
    against the server rather than against a dict.
    """
    engine = WindowedDetectionEngine(redis, rules=(_RULE,))
    tenant = str(uuid.uuid4())

    for _ in range(10):
        assert await engine.evaluate(_auth_fail(tenant, "2026-10-27T12:00:00Z"), event_id="the-same-event") == []

    keys = [k for k in await redis.keys(f"aisoc:wd:{tenant}:*") if not k.endswith(tuple(f":fired:{n}" for n in range(100)))]
    assert keys, "the observation should have been recorded"
    assert await redis.zcard(keys[0]) == 1, "ten deliveries of one event are one member"
