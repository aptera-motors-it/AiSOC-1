"""The real Postgres recurrence path for terminal alerts.

Run with ``AISOC_TEST_POSTGRES`` pointing to a disposable PostgreSQL database.
The test creates only the alert-store columns the sink writes, then exercises
the production ``AlertSink.persist`` path through asyncpg.
"""

from __future__ import annotations

import os
import uuid

import pytest
import pytest_asyncio
from app.models.alert import AlertSeverity, FusedAlert, FusionDecision, RawAlert
from app.services.alert_sink import AlertSink, PersistOutcome

DSN = os.getenv("AISOC_TEST_POSTGRES", "").strip()
pytestmark = pytest.mark.skipif(not DSN, reason="set AISOC_TEST_POSTGRES=postgresql://... to run the live recurrence proof")

_ALERTS_SCHEMA = """
CREATE TABLE alerts (
    id UUID PRIMARY KEY,
    tenant_id UUID NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL,
    status VARCHAR(30) NOT NULL,
    mitre_tactics JSONB,
    mitre_techniques JSONB,
    iocs JSONB,
    entities JSONB,
    raw_event JSONB,
    dedup_hash VARCHAR(64),
    confidence INTEGER,
    confidence_label VARCHAR(20),
    confidence_rationale JSONB,
    narrative TEXT,
    anomaly_score DOUBLE PRECISION,
    event_time TIMESTAMPTZ,
    connector_id UUID,
    connector_type VARCHAR(100),
    source_event_ids JSONB,
    ocsf_class_uid INTEGER,
    rule_id TEXT,
    rule_name TEXT,
    external_id TEXT,
    affected_hosts JSONB,
    affected_users JSONB,
    affected_ips JSONB,
    session_id UUID,
    session_key_kind TEXT,
    originating_human TEXT,
    src_ip_class TEXT,
    src_ip_class_dataset_version TEXT,
    resolved_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ
)
"""


@pytest_asyncio.fixture
async def pool():  # noqa: ANN201
    asyncpg = pytest.importorskip("asyncpg")
    schema = f"alert_sink_recurrence_{uuid.uuid4().hex}"
    admin = await asyncpg.connect(DSN)
    await admin.execute(f'CREATE SCHEMA "{schema}"')

    async def set_test_schema(conn) -> None:  # noqa: ANN001
        await conn.execute(f'SET search_path TO "{schema}"')

    created = await asyncpg.create_pool(DSN, min_size=1, max_size=2, init=set_test_schema)
    async with created.acquire() as conn:
        await conn.execute(_ALERTS_SCHEMA)
    try:
        yield created
    finally:
        await created.close()
        await admin.execute(f'DROP SCHEMA "{schema}" CASCADE')
        await admin.close()


def _fused(decision: FusionDecision) -> FusedAlert:
    raw = RawAlert(
        tenant_id=uuid.uuid4(),
        source="test detector",
        title="repeated credential access",
        severity=AlertSeverity.HIGH,
        hostname="host-1",
        mitre_techniques=["T1003"],
    )
    raw.id = raw.deterministic_id()
    return FusedAlert(id=raw.id, tenant_id=raw.tenant_id, fusion_decision=decision, alert=raw)


@pytest.mark.asyncio
async def test_a_matching_detection_reopens_a_closed_alert_in_postgres(pool) -> None:  # noqa: ANN001
    first = _fused(FusionDecision.NEW_ALERT)
    sink = AlertSink("postgresql://unused")
    sink._pool = pool

    assert (await sink.persist(first)).outcome is PersistOutcome.INSERTED
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE alerts SET status = 'closed', resolved_at = NOW() WHERE id = $1",
            first.id,
        )

    recurrence = first.model_copy(update={"fusion_decision": FusionDecision.DUPLICATE})
    result = await sink.persist(recurrence)

    assert result.outcome is PersistOutcome.DUPLICATE
    async with pool.acquire() as conn:
        row = await conn.fetchrow("SELECT status, resolved_at FROM alerts WHERE id = $1", first.id)
    assert row["status"] == "new"
    assert row["resolved_at"] is None
