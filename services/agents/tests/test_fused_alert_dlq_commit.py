"""A committed fused alert was triaged, or the DLQ accepted it.

The consume loop commits after ``_process_with_retry`` returns. That return
value is False both when the DLQ accepted the poison alert and when the
publish never happened. A broker that accepts the commit and refuses the
DLQ then drops the alert: the offset moves, and the next poll does not
see it again.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import time
import uuid

import pytest
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer, TopicPartition
from app.workers.fused_alert_consumer import FusedAlertTriageWorker

pytestmark = [pytest.mark.asyncio, pytest.mark.integration]

_LIVE_BROKER = "127.0.0.1:9092"


def _broker_up(addr: str) -> bool:
    host, _, port = addr.partition(":")
    try:
        with socket.create_connection((host, int(port)), timeout=0.4):
            return True
    except OSError:
        return False


def _closed_port() -> str:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return f"127.0.0.1:{sock.getsockname()[1]}"


def _alert(alert_id: str) -> dict:
    return {
        "id": alert_id,
        "tenant_id": "11111111-1111-1111-1111-111111111111",
        "hostname": "win-dc01",
        "alert": {"id": alert_id, "hostname": "win-dc01", "severity": "high"},
    }


async def _wait_until(predicate, timeout: float, detail: str) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.05)
    raise AssertionError(detail)


async def _release(worker: FusedAlertTriageWorker, task: asyncio.Task) -> None:
    """Unblock ``start`` without letting ``stop`` clear the consumer first.

    ``start`` stops the consumer in ``finally``. Clearing the attribute
    from ``FusedAlertTriageWorker.stop`` before that runs makes the
    finalizer call ``None.stop``.
    """
    if task.done():
        task.exception()
        return
    worker._running = False
    consumer = worker._consumer
    if consumer is not None:
        await consumer.stop()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(task, timeout=10)
    if task.done() and not task.cancelled():
        task.exception()


async def test_dead_dlq_broker_does_not_commit_the_offset(monkeypatch: pytest.MonkeyPatch) -> None:
    """Poison alert, live source broker, dead DLQ broker: offset stays put.

    The first alert is triaged and committed, so the group has a real
    checkpoint. The second alert cannot be published to the DLQ. The
    checkpoint must remain on that second alert, and the next poll of the
    same group must read it again.
    """
    if not _broker_up(_LIVE_BROKER):
        pytest.skip(f"no Kafka broker at {_LIVE_BROKER}")

    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")

    topic = f"p06-fused-{uuid.uuid4().hex[:12]}"
    group = f"p06-triage-{uuid.uuid4().hex[:12]}"
    ok_id = f"ok-{uuid.uuid4().hex[:8]}"
    poison_id = f"poison-{uuid.uuid4().hex[:8]}"
    dead_broker = _closed_port()
    triaged: list[str] = []
    commits: list[object] = []
    isolate = {"on": True}

    async def triage(message: dict) -> dict:
        triaged.append(str(message["id"]))
        if message["id"] == poison_id:
            raise RuntimeError("triage unavailable")
        return {"verdict": "needs_review"}

    worker = FusedAlertTriageWorker(
        bootstrap_servers=_LIVE_BROKER,
        topic=topic,
        group_id=group,
        max_attempts=1,
        entity_concurrency=1,
    )
    worker.triage = triage

    original_start = AIOKafkaConsumer.start

    async def start_and_isolate_dlq(self, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003
        await original_start(self, *args, **kwargs)
        if not isolate["on"]:
            return
        real_commit = self.commit

        async def commit(offsets=None):  # noqa: ANN001
            commits.append(offsets)
            return await real_commit(offsets)

        self.commit = commit
        worker._bootstrap = dead_broker

    monkeypatch.setattr(AIOKafkaConsumer, "start", start_and_isolate_dlq)

    task = asyncio.create_task(worker.start())
    try:
        await _wait_until(
            lambda: worker._consumer is not None and bool(worker._consumer.assignment()),
            30,
            "consumer was not assigned a partition",
        )

        producer = AIOKafkaProducer(
            bootstrap_servers=_LIVE_BROKER,
            value_serializer=lambda value: json.dumps(value).encode("utf-8"),
        )
        await producer.start()
        try:
            await producer.send_and_wait(topic, _alert(ok_id))
            await _wait_until(
                lambda: ok_id in triaged and len(commits) >= 1,
                20,
                f"first alert was not triaged and committed: triaged={triaged} commits={len(commits)}",
            )
            poison = await producer.send_and_wait(topic, _alert(poison_id))
        finally:
            await producer.stop()

        await _wait_until(
            lambda: task.done() or poison_id in triaged and len(commits) >= 2,
            20,
            f"poison alert was neither held nor committed: triaged={triaged} commits={len(commits)}",
        )
    finally:
        isolate["on"] = False
        await _release(worker, task)

    reader = AIOKafkaConsumer(
        topic,
        bootstrap_servers=_LIVE_BROKER,
        group_id=group,
        auto_offset_reset="latest",
        enable_auto_commit=False,
        value_deserializer=lambda raw: json.loads(raw.decode("utf-8")),
    )
    await reader.start()
    try:
        tp = TopicPartition(topic, poison.partition)
        committed = await reader.committed(tp)
        assert committed == poison.offset, (
            f"committed offset {committed} moved past poison offset {poison.offset}; a failed DLQ publish must leave the offset uncommitted"
        )
        record = await asyncio.wait_for(reader.getone(), timeout=15)
    finally:
        await reader.stop()

    assert record.value["id"] == poison_id
    assert record.offset == poison.offset
