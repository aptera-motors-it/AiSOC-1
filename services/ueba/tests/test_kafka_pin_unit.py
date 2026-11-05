from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import patch

import pytest
from aiokafka import TopicPartition
from aiokafka.errors import CommitFailedError
from app.core.config import settings
from app.services.kafka_consumer import UEBAKafkaConsumer


@dataclass
class _Msg:
    topic: str
    partition: int
    offset: int
    value: bytes


class _Consumer:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self._msgs: list[_Msg] = []
        self.commits: list[dict[TopicPartition, int]] = []
        self.fail_left = 0

    def set_messages(self, msgs: list[_Msg]) -> None:
        self._msgs = list(msgs)

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    def __aiter__(self):
        self._iter = iter(self._msgs)
        return self

    async def __anext__(self):
        try:
            return next(self._iter)
        except StopIteration as exc:
            raise StopAsyncIteration from exc

    async def commit(self, offsets: dict[TopicPartition, int] | None = None) -> None:
        assert offsets is not None
        if self.fail_left > 0:
            self.fail_left -= 1
            raise CommitFailedError("generation changed")
        self.commits.append(dict(offsets))

    async def committed(self, tp: TopicPartition) -> int | None:
        return None


class _Producer:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        pass

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None


@pytest.mark.asyncio
async def test_rejected_pins_then_dlq_fail_still_leave_a_pin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(settings, "database_url", "postgresql+asyncpg://aisoc:x@127.0.0.1:1/aisoc")
    monkeypatch.setattr(settings, "kafka_bootstrap_servers", "localhost:9092")
    monkeypatch.setattr(settings, "kafka_input_topic", "t")
    monkeypatch.setattr(settings, "kafka_output_topic", "t.out")
    monkeypatch.setattr(settings, "kafka_consumer_group", "g")

    created: list[_Consumer] = []

    def factory(*args: Any, **kwargs: Any) -> _Consumer:
        c = _Consumer(*args, **kwargs)
        c.set_messages([_Msg("t", 0, 0, b'{"event_id":"x"}')])
        c.fail_left = 2
        created.append(c)
        return c

    with (
        patch("aiokafka.AIOKafkaConsumer", factory),
        patch("aiokafka.AIOKafkaProducer", _Producer),
    ):
        consumer = UEBAKafkaConsumer()

        async def boom(_raw: bytes, _producer: Any) -> None:
            raise RuntimeError("score failed")

        async def dlq_fail(*_a: Any, **_k: Any) -> bool:
            return False

        monkeypatch.setattr(consumer, "_process_message", boom)
        monkeypatch.setattr(consumer._dlq, "record", dlq_fail)
        await consumer.run()

    c0 = created[0]
    assert c0.kwargs.get("enable_auto_commit") is False
    assert c0.commits == [{TopicPartition("t", 0): 0}], c0.commits
    assert consumer.stats()["handler_failures"] == 1
    assert consumer.stats()["dead_lettered"] == 0
