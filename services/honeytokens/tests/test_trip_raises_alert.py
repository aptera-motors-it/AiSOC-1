"""A tripped honeytoken becomes an alert on the default stack.

The shipped layout used to leave this service out of the core profile and
leave the webhook URL empty, so ``send_alert`` returned false and nothing
was written to ``alerts``. A trip taken while the receiver was down was
recorded and then never sent. These tests drive the real honeytoken app
over HTTP, the real API receiver, a real broker and the real fusion
promoter and alert sink.
"""

from __future__ import annotations

import asyncio
import os
import socket
import subprocess
import textwrap
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

import asyncpg
import httpx
import pytest

REPO = Path(__file__).resolve().parents[3]
RECEIVER = "http://api:8000/api/v1/internal/honeytoken-alerts"
COMPOSE = REPO / "docker-compose.yml"


def _clear_honeytoken_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("HONEYTOKEN_") or key == "DATABASE_URL":
            monkeypatch.delenv(key, raising=False)


def test_default_webhook_is_the_api_ingest_route(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unset URL used to skip the alert. The default is the API receiver."""
    _clear_honeytoken_env(monkeypatch)
    from app.core.config import Settings

    assert Settings().alert_webhook_url == RECEIVER


def test_empty_webhook_is_not_a_quiet_skip(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    """Clearing the URL is a failed delivery, not an informational skip."""
    _clear_honeytoken_env(monkeypatch)
    monkeypatch.setenv("HONEYTOKEN_ALERT_WEBHOOK_URL", "")
    from app.core.config import Settings
    from app.services import alerting

    monkeypatch.setattr(alerting, "settings", Settings())
    caplog.set_level("ERROR", logger="app.services.alerting")

    sent = asyncio.run(
        alerting.send_alert(
            honeytoken_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            token_type="url",
            token_name="canary",
            trigger_id=uuid.uuid4(),
            source_ip="203.0.113.10",
            triggered_at=datetime.now(UTC),
        )
    )
    assert sent is False
    assert any("alert_webhook_url" in record.message for record in caplog.records)


def test_core_compose_starts_honeytokens_with_a_receiver() -> None:
    """The default compose stack starts honeytokens and points it at the API."""
    block = _service_block(COMPOSE.read_text(), "honeytokens")
    assert "profiles:" not in block
    assert f"HONEYTOKEN_ALERT_WEBHOOK_URL: {RECEIVER}" in block
    assert "HONEYTOKEN_ALERT_WEBHOOK_SECRET:" in block


def _service_block(compose: str, name: str) -> str:
    lines = compose.splitlines()
    start = None
    for index, line in enumerate(lines):
        if line == f"  {name}:":
            start = index
            break
    if start is None:
        return ""
    end = len(lines)
    for index in range(start + 1, len(lines)):
        if lines[index].startswith("  ") and not lines[index].startswith("   ") and lines[index].rstrip().endswith(":"):
            end = index
            break
    return "\n".join(lines[start:end])


# ---------------------------------------------------------------------------
# Real path: honeytokens HTTP → API receiver → Kafka → fusion promoter + sink
# ---------------------------------------------------------------------------

_PROMOTE = textwrap.dedent(
    """
    import asyncio, json, os, sys
    sys.path.insert(0, os.environ["FUSION_PATH"])
    from aiokafka import AIOKafkaConsumer
    from app.models.alert import FusedAlert, FusionDecision
    from app.services.alert_sink import AlertSink
    from app.services.promoter import promote_normalized_event

    async def main() -> None:
        consumer = AIOKafkaConsumer(
            os.environ["TOPIC"],
            bootstrap_servers=os.environ["KAFKA_BOOTSTRAP_SERVERS"],
            group_id="honeytoken-alert-test",
            auto_offset_reset="earliest",
            enable_auto_commit=False,
        )
        await consumer.start()
        sink = AlertSink(os.environ["DATABASE_URL"])
        try:
            deadline = asyncio.get_event_loop().time() + float(os.environ.get("PROMOTE_SECONDS", "25"))
            while asyncio.get_event_loop().time() < deadline:
                batch = await consumer.getmany(timeout_ms=500, max_records=20)
                for records in batch.values():
                    for record in records:
                        payload = json.loads(record.value)
                        raw = promote_normalized_event(payload)
                        if raw is None:
                            continue
                        raw.id = raw.deterministic_id()
                        fused = FusedAlert(
                            id=raw.id,
                            tenant_id=raw.tenant_id,
                            fusion_decision=FusionDecision.NEW_INCIDENT,
                            alert=raw,
                        )
                        await sink.persist(fused)
        finally:
            await sink.stop()
            await consumer.stop()

    asyncio.run(main())
    """
)


def _database_url() -> str | None:
    return os.environ.get("AISOC_HONEYTOKEN_TEST_DATABASE_URL")


def _kafka() -> str | None:
    return os.environ.get("AISOC_HONEYTOKEN_TEST_KAFKA")


pytestmark_live = pytest.mark.skipif(
    not _database_url() or not _kafka(),
    reason="set AISOC_HONEYTOKEN_TEST_DATABASE_URL and AISOC_HONEYTOKEN_TEST_KAFKA to run the live trip",
)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_http(url: str, timeout: float, *, accept: set[int]) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            response = httpx.get(url, timeout=1.0)
        except httpx.HTTPError:
            time.sleep(0.15)
            continue
        if response.status_code in accept:
            return True
        time.sleep(0.15)
    return False


class _Proc:
    def __init__(self, proc: subprocess.Popen[bytes]) -> None:
        self.proc = proc

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def _spawn(args: list[str], env: dict[str, str], cwd: Path) -> _Proc:
    proc = subprocess.Popen(args, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return _Proc(proc)


def _python(venv: Path) -> str:
    return str(venv / "bin" / "python")


@pytest.mark.skipif(
    not _database_url() or not _kafka(),
    reason="set AISOC_HONEYTOKEN_TEST_DATABASE_URL and AISOC_HONEYTOKEN_TEST_KAFKA to run the live trip",
)
def test_trip_writes_an_alert_and_a_down_receiver_is_retried() -> None:
    """Trip once with the receiver up, and once while it is down.

    The second trip must still produce an alert after the receiver returns.
    Both rows are the fusion sink's insert of the event the API published.
    """
    database_url = _database_url()
    kafka = _kafka()
    assert database_url and kafka
    token = "honeytoken-alert-test-token-0123456789abcdef"
    tenant = uuid.uuid4()
    _prepare_database(database_url, tenant)
    api_port = _free_port()
    honey_port = _free_port()
    receiver = f"http://127.0.0.1:{api_port}/api/v1/internal/honeytoken-alerts"
    env_base = os.environ.copy()
    env_base["DATABASE_URL"] = database_url
    env_base["AISOC_SERVICE_TOKEN"] = token
    env_base["KAFKA_BOOTSTRAP_SERVERS"] = kafka
    env_base["KAFKA_TOPIC_RAW_EVENTS"] = "aisoc.raw_events"
    env_base["ENVIRONMENT"] = "development"
    env_base["PYTHONPATH"] = str(REPO / "services" / "api")

    api_env = dict(env_base)
    api = _spawn(
        [
            _python(Path(os.environ.get("AISOC_API_PYTHON", "/tmp/venv-api"))),
            "-c",
            textwrap.dedent(
                f"""
                import uvicorn
                from fastapi import FastAPI
                from app.api.v1.endpoints.honeytoken_alerts import router
                app = FastAPI()
                app.include_router(router, prefix="/api/v1")
                uvicorn.run(app, host="127.0.0.1", port={api_port}, log_level="warning")
                """
            ),
        ],
        api_env,
        REPO / "services" / "api",
    )
    honey_env = dict(env_base)
    honey_env["PYTHONPATH"] = str(REPO / "services" / "honeytokens")
    honey_env["HONEYTOKEN_ALERT_WEBHOOK_URL"] = receiver
    honey_env["HONEYTOKEN_ALERT_WEBHOOK_SECRET"] = token
    honey_env["HONEYTOKEN_ALERT_RETRY_SECONDS"] = "0.4"
    honey = _spawn(
        [
            _python(Path(os.environ.get("AISOC_HONEYTOKEN_PYTHON", "/tmp/venv-honeytokens"))),
            "-m",
            "uvicorn",
            "app.main:app",
            "--host",
            "127.0.0.1",
            "--port",
            str(honey_port),
            "--log-level",
            "warning",
        ],
        honey_env,
        REPO / "services" / "honeytokens",
    )
    promote_env = dict(env_base)
    promote_env["FUSION_PATH"] = str(REPO / "services" / "fusion")
    promote_env["TOPIC"] = "aisoc.raw_events"
    promote_env["PROMOTE_SECONDS"] = "30"
    promote_env["PYTHONPATH"] = str(REPO / "services" / "fusion")
    promote = _spawn(
        [_python(Path(os.environ.get("AISOC_API_PYTHON", "/tmp/venv-api"))), "-c", _PROMOTE],
        promote_env,
        REPO / "services" / "fusion",
    )
    try:
        assert _wait_http(f"http://127.0.0.1:{honey_port}/health", 20, accept={200}), _dump(honey)
        with httpx.Client(base_url=f"http://127.0.0.1:{honey_port}", timeout=10.0) as client:
            token_id = asyncio.run(_plant_token(database_url, tenant, "live-canary", "203.0.113.10"))
            tripped = client.post(
                "/api/v1/honeytokens/webhook/trigger",
                headers={"Authorization": f"Bearer {token}"},
                json={"token_id": str(token_id), "source_ip": "203.0.113.10"},
            )
            assert tripped.status_code == 200, tripped.text
        deadline = time.time() + 20
        while time.time() < deadline and _alert_count(database_url, tenant) < 1:
            time.sleep(0.4)
        assert _alert_count(database_url, tenant) >= 1, "a tripped honeytoken produced no alert row"

        # Receiver outage: stop the API, trip again, bring it back, and the
        # retry loop must deliver the trip that happened in between.
        api.stop()
        time.sleep(0.3)
        api_port_2 = _free_port()
        receiver_2 = f"http://127.0.0.1:{api_port_2}/api/v1/internal/honeytoken-alerts"
        # The running honeytoken process keeps the URL it started with, so the
        # outage is that process's receiver. Stop it, trip against a fresh
        # process pointed at a closed port, then start the receiver there.
        honey.stop()
        closed = _free_port()
        honey_env["HONEYTOKEN_ALERT_WEBHOOK_URL"] = f"http://127.0.0.1:{closed}/api/v1/internal/honeytoken-alerts"
        honey_port = _free_port()
        honey = _spawn(
            [
                _python(Path(os.environ.get("AISOC_HONEYTOKEN_PYTHON", "/tmp/venv-honeytokens"))),
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(honey_port),
                "--log-level",
                "warning",
            ],
            honey_env,
            REPO / "services" / "honeytokens",
        )
        assert _wait_http(f"http://127.0.0.1:{honey_port}/health", 20, accept={200}), _dump(honey)
        with httpx.Client(base_url=f"http://127.0.0.1:{honey_port}", timeout=10.0) as client:
            token_id = asyncio.run(_plant_token(database_url, tenant, "outage-canary", "203.0.113.20"))
            tripped = client.post(
                "/api/v1/honeytokens/webhook/trigger",
                headers={"Authorization": f"Bearer {token}"},
                json={"token_id": str(token_id), "source_ip": "203.0.113.20"},
            )
            assert tripped.status_code == 200, tripped.text
            assert tripped.json()["alert_sent"] is False
        before = _alert_count(database_url, tenant)
        api_env_2 = dict(api_env)
        api = _spawn(
            [
                _python(Path(os.environ.get("AISOC_API_PYTHON", "/tmp/venv-api"))),
                "-c",
                textwrap.dedent(
                    f"""
                    import uvicorn
                    from fastapi import FastAPI
                    from app.api.v1.endpoints.honeytoken_alerts import router
                    app = FastAPI()
                    app.include_router(router, prefix="/api/v1")
                    uvicorn.run(app, host="127.0.0.1", port={api_port_2}, log_level="warning")
                    """
                ),
            ],
            api_env_2,
            REPO / "services" / "api",
        )
        assert _wait_http(receiver_2, 20, accept={401, 403, 422, 405}), _dump(api)
        # The honeytoken process is still aimed at `closed`. Point a new one
        # at the restored receiver; the unsent row is what the retry sends.
        honey.stop()
        honey_env["HONEYTOKEN_ALERT_WEBHOOK_URL"] = receiver_2
        honey_port = _free_port()
        honey = _spawn(
            [
                _python(Path(os.environ.get("AISOC_HONEYTOKEN_PYTHON", "/tmp/venv-honeytokens"))),
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(honey_port),
                "--log-level",
                "warning",
            ],
            honey_env,
            REPO / "services" / "honeytokens",
        )
        assert _wait_http(f"http://127.0.0.1:{honey_port}/health", 20, accept={200}), _dump(honey)
        deadline = time.time() + 12
        while time.time() < deadline and _alert_count(database_url, tenant) <= before:
            time.sleep(0.4)
        assert _alert_count(database_url, tenant) > before, "a trip taken while the receiver was down was never sent"
    finally:
        api.stop()
        honey.stop()
        promote.stop()


def _prepare_database(database_url: str, tenant: uuid.UUID) -> None:
    """Apply the real API and honeytoken schemas, then insert the tenant the sink requires."""
    api_python = _python(Path(os.environ.get("AISOC_API_PYTHON", "/tmp/venv-api")))
    honey_python = _python(Path(os.environ.get("AISOC_HONEYTOKEN_PYTHON", "/tmp/venv-honeytokens")))
    api_env = os.environ.copy()
    api_env["DATABASE_URL"] = database_url
    api_env["PYTHONPATH"] = str(REPO / "services" / "api")
    api_env["ENVIRONMENT"] = "development"
    migrated = subprocess.run(
        [api_python, "-m", "app.scripts.run_migrations"],
        cwd=REPO / "services" / "api",
        env=api_env,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )
    assert migrated.returncode == 0, migrated.stdout + migrated.stderr
    honey_env = os.environ.copy()
    honey_env["DATABASE_URL"] = database_url
    upgraded = subprocess.run(
        [honey_python, "-m", "alembic", "upgrade", "head"],
        cwd=REPO / "services" / "honeytokens",
        env=honey_env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert upgraded.returncode == 0, upgraded.stdout + upgraded.stderr
    asyncio.run(_insert_tenant(database_url, tenant))


async def _insert_tenant(database_url: str, tenant: uuid.UUID) -> None:
    conn = await asyncpg.connect(_asyncpg_dsn(database_url))
    try:
        await conn.execute(
            """
            INSERT INTO tenants (id, name, slug, plan, is_active, settings, limits)
            VALUES ($1, 'honeytoken-canary', $2, 'starter', true, '{}'::jsonb, '{}'::jsonb)
            ON CONFLICT (id) DO NOTHING
            """,
            tenant,
            f"canary-{tenant.hex[:12]}",
        )
    finally:
        await conn.close()


async def _plant_token(database_url: str, tenant: uuid.UUID, name: str, source_label: str) -> uuid.UUID:
    """Insert one token. The trip itself is the webhook, which is what has to alert."""
    token_id = uuid.uuid4()
    conn = await asyncpg.connect(_asyncpg_dsn(database_url))
    try:
        await conn.execute(
            """
            INSERT INTO honeytokens (id, tenant_id, name, token_type, token_value, status)
            VALUES ($1, $2, $3, 'url', $4, 'active')
            """,
            token_id,
            tenant,
            name,
            f"http://canary.example/{source_label}/{token_id}",
        )
    finally:
        await conn.close()
    return token_id


def _alert_count(database_url: str, tenant: uuid.UUID) -> int:
    async def _count() -> int:
        conn = await asyncpg.connect(_asyncpg_dsn(database_url))
        try:
            return int(
                await conn.fetchval(
                    "SELECT count(*) FROM alerts WHERE tenant_id = $1 AND title LIKE 'Honeytoken tripped:%'",
                    tenant,
                )
            )
        finally:
            await conn.close()

    return asyncio.run(_count())


def _asyncpg_dsn(url: str) -> str:
    if url.startswith("postgresql+asyncpg://"):
        return "postgresql://" + url[len("postgresql+asyncpg://") :]
    return url


def _dump(proc: _Proc) -> str:
    stdout = proc.proc.stdout
    if stdout is None:
        return ""
    os.set_blocking(stdout.fileno(), False)
    try:
        out = os.read(stdout.fileno(), 4000)
    except BlockingIOError:
        return ""
    return out.decode("utf-8", errors="replace")
