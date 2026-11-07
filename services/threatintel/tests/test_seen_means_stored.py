from __future__ import annotations

import asyncio
import os
import uuid
from typing import Any

import pytest
import redis.asyncio as aioredis
from app.feeds.pipeline import ThreatIntelPipeline
from app.storage.bloom import RedisBloomFilter
from app.storage.neo4j import Neo4jStore
from app.storage.opensearch import OpenSearchStore
from app.storage.qdrant import QdrantStore
from neo4j import AsyncGraphDatabase
from opensearchpy import AsyncOpenSearch
from qdrant_client import AsyncQdrantClient

pytestmark = pytest.mark.asyncio

_REDIS_URL = os.environ.get("AISOC_TEST_REDIS", "redis://127.0.0.1:6379/15")


@pytest.fixture(autouse=True)
def _embedding_stays_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """A dead Qdrant still embeds before it connects. Do not download a model to prove that."""

    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("HF_HUB_DISABLE_TELEMETRY", "1")


class _Recording:
    def __init__(self) -> None:
        self.values: list[str] = []

    async def bulk_index_iocs(self, iocs: list[dict[str, Any]]) -> int:
        self.values.extend(str(row["value"]) for row in iocs)
        return len(iocs)

    async def upsert_iocs(self, iocs: list[dict[str, Any]], **_kwargs: Any) -> None:
        self.values.extend(str(row["value"]) for row in iocs)


class _Bus:
    def __init__(self) -> None:
        self.sent: list[bytes] = []

    async def send(self, _topic: str, value: bytes) -> None:
        self.sent.append(value)


class _Unreachable:
    def __init__(self) -> None:
        self.opensearch = AsyncOpenSearch(
            hosts=[{"host": "127.0.0.1", "port": 1}],
            timeout=1,
            max_retries=0,
            retry_on_timeout=False,
        )
        self.qdrant = AsyncQdrantClient(url="http://127.0.0.1:1", timeout=1, check_compatibility=False)
        self.neo4j = AsyncGraphDatabase.driver(
            "bolt://127.0.0.1:1",
            auth=("neo4j", "x"),
            connection_timeout=1,
            connection_acquisition_timeout=1,
            max_transaction_retry_time=1,
        )

    def pipeline(
        self,
        bloom: RedisBloomFilter,
        *,
        kafka_producer: Any | None = None,
        os_store: Any | None = None,
        qdrant_store: Any | None = None,
        neo4j_store: Any | None = None,
    ) -> ThreatIntelPipeline:
        return ThreatIntelPipeline(
            bloom=bloom,
            os_store=OpenSearchStore(self.opensearch) if os_store is None else os_store,
            qdrant_store=QdrantStore(self.qdrant) if qdrant_store is None else qdrant_store,
            neo4j_store=Neo4jStore(self.neo4j) if neo4j_store is None else neo4j_store,
            kafka_producer=kafka_producer,
        )

    async def close(self) -> None:
        await self.opensearch.close()
        await self.qdrant.close()
        await self.neo4j.close()


def _feed() -> list[dict[str, str]]:
    return [{"type": "ip", "value": f"203.0.113.{n}", "source": "kev"} for n in range(1, 4)]


def _values(feed: list[dict[str, str]]) -> list[str]:
    return [row["value"] for row in feed]


async def _redis() -> aioredis.Redis:
    client = aioredis.from_url(_REDIS_URL, decode_responses=False)
    try:
        await asyncio.wait_for(client.ping(), timeout=2)
    except Exception as exc:
        await client.aclose()
        pytest.skip(f"Redis is not reachable at {_REDIS_URL}: {exc}")
    return client


def _bloom(client: aioredis.Redis) -> tuple[str, RedisBloomFilter]:
    key = f"threatintel:test:seen:{uuid.uuid4().hex}"
    return key, RedisBloomFilter(client, key=key)


async def test_an_outage_is_stored_on_the_next_refresh() -> None:
    client = await _redis()
    key, bloom = _bloom(client)
    feed = _feed()
    down = _Unreachable()
    bus = _Bus()
    try:
        first = await down.pipeline(bloom, kafka_producer=bus).ingest_iocs(feed, source="kev")
        assert first["new"] == 3
        assert first["duplicate"] == 0
        assert first["sinks"] == {"opensearch": None, "qdrant": None, "neo4j": None}

        stored = _Recording()
        second = await ThreatIntelPipeline(
            bloom=bloom,
            os_store=stored,  # type: ignore[arg-type]
            qdrant_store=stored,  # type: ignore[arg-type]
            neo4j_store=stored,  # type: ignore[arg-type]
            kafka_producer=bus,
        ).ingest_iocs(feed, source="kev")
        assert second["duplicate"] == 0, second
        assert second["new"] == 3
        assert stored.values == _values(feed) * 3
        assert len(bus.sent) == len(feed)
    finally:
        await down.close()
        await client.delete(key)
        await client.aclose()


async def test_a_qdrant_outage_is_stored_when_qdrant_returns() -> None:
    client = await _redis()
    key, bloom = _bloom(client)
    feed = _feed()
    down = _Unreachable()
    accepted = _Recording()
    try:
        first = await down.pipeline(
            bloom,
            os_store=accepted,
            neo4j_store=accepted,
        ).ingest_iocs(feed, source="kev")
        assert first["new"] == 3
        assert first["sinks"]["opensearch"] == 3
        assert first["sinks"]["neo4j"] == 3
        assert first["sinks"]["qdrant"] is None

        console = _Recording()
        second = await ThreatIntelPipeline(
            bloom=bloom,
            os_store=_Recording(),  # type: ignore[arg-type]
            qdrant_store=console,  # type: ignore[arg-type]
            neo4j_store=_Recording(),  # type: ignore[arg-type]
        ).ingest_iocs(feed, source="kev")
        assert second["duplicate"] == 0, second
        assert second["new"] == 3
        assert console.values == _values(feed)
    finally:
        await down.close()
        await client.delete(key)
        await client.aclose()


async def test_a_qdrant_write_is_not_repeated() -> None:
    client = await _redis()
    key, bloom = _bloom(client)
    feed = _feed()
    down = _Unreachable()
    console = _Recording()
    try:
        first = await down.pipeline(bloom, qdrant_store=console).ingest_iocs(feed, source="kev")
        assert first["new"] == 3
        assert first["sinks"]["qdrant"] == 3
        assert first["sinks"]["opensearch"] is None
        assert first["sinks"]["neo4j"] is None
        assert console.values == _values(feed)

        second = await down.pipeline(bloom, qdrant_store=console).ingest_iocs(feed, source="kev")
        assert second["new"] == 0
        assert second["duplicate"] == 3
        assert console.values == _values(feed)
    finally:
        await down.close()
        await client.delete(key)
        await client.aclose()


async def test_a_value_repeated_in_one_batch_is_stored_once() -> None:
    client = await _redis()
    key, bloom = _bloom(client)
    feed = [{"type": "ip", "value": "203.0.113.9", "source": "kev"}] * 2
    stored = _Recording()
    try:
        stats = await ThreatIntelPipeline(
            bloom=bloom,
            os_store=stored,  # type: ignore[arg-type]
            qdrant_store=stored,  # type: ignore[arg-type]
            neo4j_store=stored,  # type: ignore[arg-type]
        ).ingest_iocs(feed, source="kev")
        assert stats["new"] == 1
        assert stats["duplicate"] == 1
        assert stored.values == ["203.0.113.9"] * 3
    finally:
        await client.delete(key)
        await client.aclose()
