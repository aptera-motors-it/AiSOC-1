"""A fused alert redelivered after a crash continues its playbook run.

The triage worker commits a fused alert's offset only after triage, so a
replica that dies before committing hands the record to the next replica,
whose dedup cache is empty. That delivery reaches the playbook trigger
again, and must not enrich again or put a second approval in front of the
analyst for one alert. A run waiting on an approval keeps waiting for its
decision; a run whose timer wait has come due continues at the next step.

The real worker reads a real topic and triages through its production sinks
on Postgres. The stand-ins are an HTTP receiver at the enrichment, realtime
and API addresses, which answers and counts what reached it; deterministic
triage in place of a model, with graph escalation off; a playbook store in a
temporary directory that holds the test playbooks; and a `resume_at` moved
into the past in place of waiting out the timer.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import pytest_asyncio

# Skip as a *module*: the offline isolation job collects this directory with
# no stores running.
pytestmark = [
    pytest.mark.asyncio,
    pytest.mark.skipif(
        not (os.environ.get("ISOLATION_PLAYBOOK_DSN", "").strip() and os.environ.get("ISOLATION_KAFKA_BROKERS", "").strip()),
        reason="ISOLATION_PLAYBOOK_DSN and ISOLATION_KAFKA_BROKERS are not set; this suite needs live infrastructure",
    ),
]

# `app` and the store drivers are imported inside the functions: that same
# offline job collects this module without the agents service on its path.

_WAIT_SECONDS = 60.0
_SOURCE_IP = "203.0.113.45"
#: What the step after each playbook's pause enriches, so a request from that
#: step cannot be mistaken for the first step's.
_BEHIND_THE_PAUSE = "198.51.100.7"


class _Receiver(ThreadingHTTPServer):
    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.calls: list[str] = []
        self.enriched: list[str] = []

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


class _Handler(BaseHTTPRequestHandler):
    server: _Receiver

    def do_POST(self) -> None:  # noqa: N802 - http.server's name
        request = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.server.calls.append(self.path)
        if self.path == "/enrich":
            self.server.enriched.append(json.loads(request)["value"])
        body = {"id": str(uuid.uuid4())} if self.path == "/api/v1/approvals" else {}
        payload = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def receiver():
    server = _Receiver()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


@pytest_asyncio.fixture
async def tenant():
    asyncpg = pytest.importorskip("asyncpg")
    dsn = os.environ["ISOLATION_PLAYBOOK_DSN"].strip()
    tenant_id = uuid.uuid4()
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute(
            "INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)",
            tenant_id,
            f"redelivery-{tenant_id.hex[:8]}",
            f"redelivery-{tenant_id.hex[:8]}",
        )
    finally:
        await conn.close()
    yield str(tenant_id)
    # The tenant row stays: triage wrote investigation_events under it, and
    # those refuse the DELETE a tenant cascade would issue.
    conn = await asyncpg.connect(dsn)
    try:
        await conn.execute("DELETE FROM aisoc_playbook_pauses WHERE tenant_id = $1", tenant_id)
    finally:
        await conn.close()


@pytest_asyncio.fixture
async def live_service(monkeypatch, tmp_path, receiver, tenant):  # noqa: ANN001
    from app.core import cost_governor
    from app.investigator import ledger
    from app.memory import institutional
    from app.playbook import engine
    from app.playbook.models import Playbook, PlaybookStep, StepType
    from app.playbook.store import PlaybookStore

    monkeypatch.setenv("DATABASE_URL", os.environ["ISOLATION_PLAYBOOK_DSN"].strip())
    monkeypatch.setenv("AISOC_DETERMINISTIC", "1")
    monkeypatch.setenv("AISOC_AGENT_ESCALATE_TO_GRAPH", "0")
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "redelivery-live-token")
    monkeypatch.setenv("AISOC_API_URL", receiver.url)
    monkeypatch.setattr(engine, "_ENRICHMENT_URL", receiver.url)
    monkeypatch.setattr(engine, "_REALTIME_URL", receiver.url)

    (tmp_path / "pack").mkdir()
    store = PlaybookStore(store_dir=tmp_path / "store", pack_root=tmp_path / "pack")
    after_pause = PlaybookStep(id="recheck", name="Enrich the next hop", type=StepType.ENRICH, params={"ioc": _BEHIND_THE_PAUSE})
    approval = store.create(
        Playbook(
            name="Enrich, then contain with sign-off",
            trigger={"on": "alert", "severity": ["high"]},
            steps=[
                PlaybookStep(id="enrich", name="Enrich the source address", type=StepType.ENRICH),
                PlaybookStep(id="gate", name="Analyst approves containment", type=StepType.APPROVAL),
                after_pause,
            ],
        ),
        tenant_id=tenant,
    )
    wait = store.create(
        Playbook(
            name="Enrich, then check again in ten minutes",
            trigger={"on": "alert", "severity": ["critical"]},
            steps=[
                PlaybookStep(id="enrich", name="Enrich the source address", type=StepType.ENRICH),
                PlaybookStep(id="hold", name="Give the beacon time to recur", type=StepType.WAIT, params={"seconds": 600}),
                after_pause,
            ],
        ),
        tenant_id=tenant,
    )
    monkeypatch.setattr(PlaybookStore, "_instance", store)
    monkeypatch.setenv("AISOC_ALERT_PLAYBOOKS_ENABLED", "1")
    monkeypatch.setenv("AISOC_ALERT_PLAYBOOKS_LIVE", f"{tenant}:{approval.id},{tenant}:{wait.id}")

    cost_governor.reset_governor()
    yield
    cost_governor.reset_governor()
    await ledger.close_pool()
    await institutional.close_pool()


def _fused_alert(tenant: str, severity: str) -> dict:
    alert_id = str(uuid.uuid4())
    return {
        "id": alert_id,
        "alert_row_id": alert_id,
        "persist_outcome": "inserted",
        "tenant_id": tenant,
        "incident_id": None,
        "fusion_decision": "new",
        "alert": {
            "id": alert_id,
            "tenant_id": tenant,
            "title": "Outbound beacon to a known C2 address",
            "rule_id": "redelivery-live",
            "severity": severity,
            "src_ip": _SOURCE_IP,
            "hostname": "WIN-FIN-02",
        },
    }


async def _set_committed(brokers: str, group: str, topic: str, partition: int, offset: int) -> None:
    """Commit ``offset`` for the group, so the next replica starts at that record.

    The first call keeps a new group, which the worker starts at the end of the
    topic, from skipping the record. The second puts the offset back where a
    replica that crashed before committing leaves it.
    """
    from aiokafka import AIOKafkaConsumer, TopicPartition
    from aiokafka.structs import OffsetAndMetadata

    consumer = AIOKafkaConsumer(bootstrap_servers=brokers, group_id=group, enable_auto_commit=False)
    await consumer.start()
    try:
        tp = TopicPartition(topic, partition)
        consumer.assign([tp])
        await consumer.commit({tp: OffsetAndMetadata(offset, "")})
    finally:
        await consumer.stop()


async def _committed(brokers: str, group: str, topic: str, partition: int) -> int | None:
    from aiokafka import TopicPartition
    from aiokafka.admin import AIOKafkaAdminClient

    admin = AIOKafkaAdminClient(bootstrap_servers=brokers)
    await admin.start()
    try:
        offsets = await admin.list_consumer_group_offsets(group)
    finally:
        await admin.close()
    found = offsets.get(TopicPartition(topic, partition))
    return found.offset if found is not None else None


async def _consume_once(brokers: str, group: str, topic: str, partition: int, offset: int) -> None:
    from app.workers.fused_alert_consumer import FusedAlertTriageWorker

    worker = FusedAlertTriageWorker(bootstrap_servers=brokers, topic=topic, group_id=group)
    task = asyncio.create_task(worker.start())
    try:
        deadline = time.monotonic() + _WAIT_SECONDS
        while ((await _committed(brokers, group, topic, partition)) or 0) <= offset:
            assert not task.done(), f"the worker stopped before committing: {task.exception()!r}"
            assert time.monotonic() < deadline, "the worker never committed the alert"
            await asyncio.sleep(0.5)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await worker.stop()


async def _pauses(tenant: str) -> list[dict]:
    import asyncpg

    conn = await asyncpg.connect(os.environ["ISOLATION_PLAYBOOK_DSN"].strip())
    try:
        rows = await conn.fetch(
            "SELECT run_id, run_context->>'_run_id' AS context_run_id, kind, status FROM aisoc_playbook_pauses WHERE tenant_id = $1::uuid",
            tenant,
        )
    finally:
        await conn.close()
    return [dict(row) for row in rows]


async def _deliver(tenant: str, severity: str) -> tuple[str, str, str, int, int]:
    from aiokafka import AIOKafkaProducer

    brokers = os.environ["ISOLATION_KAFKA_BROKERS"].strip()
    topic = f"aisoc.alerts.fused.redelivery.{uuid.uuid4().hex[:8]}"
    group = f"aisoc-agents-triage-{uuid.uuid4().hex[:8]}"

    producer = AIOKafkaProducer(bootstrap_servers=brokers)
    await producer.start()
    try:
        record = await producer.send_and_wait(topic, json.dumps(_fused_alert(tenant, severity)).encode())
    finally:
        await producer.stop()
    await _set_committed(brokers, group, topic, record.partition, record.offset)
    await _consume_once(brokers, group, topic, record.partition, record.offset)
    return brokers, group, topic, record.partition, record.offset


async def _crash_and_redeliver(brokers: str, group: str, topic: str, partition: int, offset: int) -> None:
    """The commit never reached the broker, and the next replica has nothing cached."""
    from app.core import cost_governor
    from app.workers.fused_alert_consumer import FusedAlertTriageWorker

    await _set_committed(brokers, group, topic, partition, offset)
    cost_governor.reset_governor()
    before = FusedAlertTriageWorker.get_metrics()

    await _consume_once(brokers, group, topic, partition, offset)

    after = FusedAlertTriageWorker.get_metrics()
    delta = {key: after[key] - before[key] for key in ("triaged", "deduplicated", "outcome_suppressed", "shadow_triaged")}
    assert delta == {"triaged": 1, "deduplicated": 0, "outcome_suppressed": 0, "shadow_triaged": 0}, (
        f"the redelivered alert did not reach the playbook trigger, so this test proves nothing: {delta}"
    )


async def test_a_redelivered_alert_does_not_start_its_playbook_again(live_service, receiver, tenant) -> None:  # noqa: ANN001
    delivery = await _deliver(tenant, "high")

    # The first delivery has to have run the playbook to its approval, or
    # the assertions after the redelivery hold for a run that never started.
    assert receiver.enriched == [_SOURCE_IP], receiver.calls
    assert receiver.calls.count("/api/v1/approvals") == 1, receiver.calls
    pauses = await _pauses(tenant)
    assert len(pauses) == 1
    (pause,) = pauses
    assert pause["context_run_id"] == pause["run_id"], "the run's context names a different run than the one that paused"

    await _crash_and_redeliver(*delivery)

    assert _BEHIND_THE_PAUSE not in receiver.enriched, "the redelivery ran the step behind the approval with no decision"
    assert receiver.enriched == [_SOURCE_IP], f"the redelivery enriched the indicator again: {receiver.calls}"
    assert receiver.calls.count("/api/v1/approvals") == 1, f"the redelivery asked for a second approval: {receiver.calls}"
    pauses = await _pauses(tenant)
    assert len(pauses) == 1, "the redelivery started a second run of the same playbook for the same alert"
    assert pauses[0]["status"] == "waiting", "the approval stopped waiting for its decision"


async def test_a_redelivered_alert_resumes_its_run_once_the_wait_is_due(live_service, receiver, tenant) -> None:  # noqa: ANN001
    import asyncpg

    delivery = await _deliver(tenant, "critical")

    assert receiver.enriched == [_SOURCE_IP], receiver.calls
    (pause,) = await _pauses(tenant)
    assert (pause["kind"], pause["status"]) == ("wait", "waiting")

    # Nothing sweeps due waits in this process, so the redelivery is the only
    # thing that can resume the run.
    conn = await asyncpg.connect(os.environ["ISOLATION_PLAYBOOK_DSN"].strip())
    try:
        await conn.execute(
            "UPDATE aisoc_playbook_pauses SET resume_at = NOW() - interval '1 second' WHERE run_id = $1",
            pause["run_id"],
        )
    finally:
        await conn.close()

    await _crash_and_redeliver(*delivery)

    assert receiver.enriched == [_SOURCE_IP, _BEHIND_THE_PAUSE], (
        f"the redelivery did not resume the run at the step after its due wait: {receiver.enriched}"
    )
    pauses = await _pauses(tenant)
    assert len(pauses) == 1, "the redelivery started a second run instead of resuming the first"
    assert pauses[0]["status"] == "resumed"

    await _crash_and_redeliver(*delivery)

    assert receiver.enriched == [_SOURCE_IP, _BEHIND_THE_PAUSE], f"a delivery after the resume ran the playbook again: {receiver.enriched}"
    assert len(await _pauses(tenant)) == 1
