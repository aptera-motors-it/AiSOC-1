from __future__ import annotations

import asyncio
import json
import os
import socket
import time
import uuid

import pytest
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer, TopicPartition
from aiokafka.admin import AIOKafkaAdminClient, NewTopic
from app.core.config import settings
from app.services.kafka_consumer import UEBAKafkaConsumer

NOT_JSON = b"{"
SCOREABLE = {
    "event_id": "0b6f8f0e-6c55-4b55-9f43-1f0d1c1e2a01",
    "tenant_id": "6f1d3f9a-1c2b-4c1d-9a8e-3b4c5d6e7f80",
    "entity_type": "user",
    "entity_id": "alice@example.com",
    "event_type": "login",
    "features": {"hour_of_day": 3, "login_count": 40},
}


def _broker() -> str:
    raw = os.environ.get("ISOLATION_KAFKA_BROKERS", "localhost:9092").split(",")[0].strip()
    host, sep, port_s = raw.partition(":")
    port = int(port_s) if sep else 9092
    with socket.socket() as sock:
        sock.settimeout(0.4)
        try:
            sock.connect((host, port))
        except OSError:
            pytest.skip(f"no Kafka broker at {raw}")
    return raw


async def _create_topic(brokers: str, topic: str) -> None:
    admin = AIOKafkaAdminClient(bootstrap_servers=brokers, security_protocol="PLAINTEXT")
    await admin.start()
    try:
        await admin.create_topics([NewTopic(topic, 1, 1)])
    finally:
        await admin.close()


async def _produce(brokers: str, topic: str, payloads: list[bytes]) -> None:
    producer = AIOKafkaProducer(bootstrap_servers=brokers, security_protocol="PLAINTEXT")
    await producer.start()
    try:
        for payload in payloads:
            await producer.send_and_wait(topic, payload)
    finally:
        await producer.stop()


async def _committed(brokers: str, group: str, topic: str) -> int | None:
    probe = AIOKafkaConsumer(
        bootstrap_servers=brokers,
        group_id=group,
        enable_auto_commit=False,
        security_protocol="PLAINTEXT",
    )
    await probe.start()
    try:
        return await probe.committed(TopicPartition(topic, 0))
    finally:
        await probe.stop()


async def _until(predicate, timeout: float, detail: str):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        await asyncio.sleep(0.05)
    raise AssertionError(detail)


@pytest.mark.asyncio
async def test_postgres_down_does_not_commit_the_scoreable_offset(monkeypatch: pytest.MonkeyPatch) -> None:
    brokers = _broker()
    suffix = uuid.uuid4().hex[:8]
    topic = f"ueba.commit.{suffix}"
    group = f"ueba-commit-{suffix}"
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.delenv("KAFKA_SECURITY_PROTOCOL", raising=False)
    monkeypatch.setattr(settings, "database_url", "postgresql+asyncpg://aisoc:x@127.0.0.1:1/aisoc")
    monkeypatch.setattr(settings, "kafka_bootstrap_servers", brokers)
    monkeypatch.setattr(settings, "kafka_input_topic", topic)
    monkeypatch.setattr(settings, "kafka_output_topic", f"{topic}.out")
    monkeypatch.setattr(settings, "kafka_consumer_group", group)

    await _create_topic(brokers, topic)
    consumer = UEBAKafkaConsumer()
    task = asyncio.create_task(consumer.run())
    try:
        await _until(lambda: consumer.attached, 20, "consumer did not attach")
        await _produce(
            brokers,
            topic,
            [NOT_JSON, json.dumps(SCOREABLE).encode(), NOT_JSON],
        )
        await _until(
            lambda: consumer.stats()["handler_failures"] >= 1,
            30,
            f"scoreable event never failed the handler: {consumer.stats()}",
        )
        consumer.stop()
        if not task.done():
            await _produce(brokers, topic, [b"wake"])
            await asyncio.wait_for(task, 30)
        if task.done() and not task.cancelled():
            error = task.exception()
            if error is not None:
                raise error
        committed = await _committed(brokers, group, topic)
        stats = consumer.stats()
        assert stats["handler_failures"] == 1
        assert stats["dead_lettered"] == 0
        assert committed == 1, f"committed offset {committed} after a scoreable event with Postgres down; stats={stats}"
    finally:
        consumer.stop()
        if not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        await consumer._engine.dispose()
