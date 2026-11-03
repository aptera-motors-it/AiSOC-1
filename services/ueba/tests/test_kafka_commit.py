from __future__ import annotations

import asyncio
import json
import os
import socket
import time
import uuid
from typing import Any

import pytest
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer, TopicPartition
from aiokafka.admin import AIOKafkaAdminClient, NewTopic
from aiokafka.errors import IllegalStateError
from app.core.config import settings
from app.services.dead_letters import DeadLetterSink
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


async def _stop(consumer: UEBAKafkaConsumer, task: asyncio.Task[None]) -> None:
    consumer.stop()
    if not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    await consumer._engine.dispose()


@pytest.mark.asyncio
async def test_restart_redelivers_a_failed_first_event(monkeypatch: pytest.MonkeyPatch) -> None:
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
    first = UEBAKafkaConsumer()
    first_task = asyncio.create_task(first.run())
    try:
        await _until(lambda: first.attached, 20, "first consumer did not attach")
        await _produce(brokers, topic, [json.dumps(SCOREABLE).encode()])
        await _until(lambda: first_task.done(), 30, f"first consumer kept running: {first.stats()}")
        if not first_task.cancelled():
            error = first_task.exception()
            if error is not None:
                raise error
        assert first.stats()["handler_failures"] == 1
        assert first.stats()["dead_lettered"] == 0
    finally:
        await _stop(first, first_task)

    second = UEBAKafkaConsumer()
    second_task = asyncio.create_task(second.run())
    try:
        await _until(
            lambda: second.stats()["handler_failures"] >= 1 or second_task.done(),
            20,
            f"restart skipped the failed first event: {second.stats()}",
        )
        if second_task.done() and not second_task.cancelled():
            error = second_task.exception()
            if error is not None:
                raise error
        assert second.stats()["handler_failures"] >= 1, second.stats()
        committed = await _committed(brokers, group, topic)
        assert committed == 0, f"committed offset {committed} moved past the failed first event"
    finally:
        await _stop(second, second_task)


@pytest.mark.asyncio
async def test_new_group_skips_events_produced_before_subscribe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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
    await _produce(brokers, topic, [json.dumps(SCOREABLE).encode()])
    consumer = UEBAKafkaConsumer()
    task = asyncio.create_task(consumer.run())
    try:
        await _until(lambda: consumer.attached, 20, "consumer did not attach")
        await asyncio.sleep(2)
        assert consumer.stats()["handler_failures"] == 0
        assert consumer.stats()["processed"] == 0
        await _produce(brokers, topic, [json.dumps(SCOREABLE).encode()])
        await _until(
            lambda: consumer.stats()["handler_failures"] >= 1 or task.done(),
            20,
            f"event produced after subscribe was not handled: {consumer.stats()}",
        )
        assert consumer.stats()["handler_failures"] == 1
    finally:
        await _stop(consumer, task)


@pytest.mark.asyncio
async def test_deeply_nested_json_reaches_the_dead_letter_sink(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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

    calls = 0
    real_record = DeadLetterSink.record

    async def spy(self: DeadLetterSink, **kwargs: Any) -> bool:
        nonlocal calls
        calls += 1
        return await real_record(self, **kwargs)

    monkeypatch.setattr(DeadLetterSink, "record", spy)
    await _create_topic(brokers, topic)
    consumer = UEBAKafkaConsumer()
    task = asyncio.create_task(consumer.run())
    try:
        await _until(lambda: consumer.attached, 20, "consumer did not attach")
        nested = b"[" * 50000 + b"]" * 50000
        await _produce(brokers, topic, [NOT_JSON, nested])
        await _until(lambda: task.done(), 20, f"nested event did not finish: {consumer.stats()}")
        error = task.exception() if not task.cancelled() else None
        assert error is None, error
        assert calls == 1
        committed = await _committed(brokers, group, topic)
        assert committed == 1, f"committed offset {committed} moved past an undelivered dead letter"
    finally:
        await _stop(consumer, task)


@pytest.mark.asyncio
async def test_lost_partition_on_commit_keeps_the_subscription(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    brokers = _broker()
    real_commit = AIOKafkaConsumer.commit

    async def commit(self: AIOKafkaConsumer, offsets: Any = None) -> None:
        if offsets and any(isinstance(offset, int) and offset > 0 for offset in offsets.values()):
            raise IllegalStateError("Partition is not assigned")
        await real_commit(self, offsets)

    monkeypatch.setattr(AIOKafkaConsumer, "commit", commit)
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
        await _produce(brokers, topic, [NOT_JSON, NOT_JSON])
        await _until(
            lambda: consumer.stats()["processed"] >= 2 or task.done(),
            20,
            f"subscription stopped after a lost partition: {consumer.stats()}",
        )
        if task.done() and not task.cancelled():
            error = task.exception()
            raise AssertionError(f"subscription ended: {error!r}")
        assert consumer.stats()["processed"] >= 2
        committed = await _committed(brokers, group, topic)
        assert committed == 0, f"committed offset {committed} advanced after a lost partition"
    finally:
        await _stop(consumer, task)
