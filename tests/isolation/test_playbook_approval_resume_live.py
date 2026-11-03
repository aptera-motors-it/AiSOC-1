from __future__ import annotations

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import pytest_asyncio

pytestmark = [
    pytest.mark.asyncio(loop_scope="module"),
    pytest.mark.skipif(
        not os.environ.get("ISOLATION_PLAYBOOK_DSN", "").strip(),
        reason="ISOLATION_PLAYBOOK_DSN is not set; this suite needs a live Postgres",
    ),
]

SERVICE_TOKEN = "approval-resume-service-token-not-a-real-secret"
CONSOLE_SECRET = "approval-resume-console-secret-at-least-32-chars"
TENANT_HEADER = "X-AiSOC-Tenant-ID"
DEADLINE_SECONDS = 4

_AGENTS = Path(__file__).resolve().parents[2] / "services" / "agents"


def _dsn() -> str:
    return os.environ["ISOLATION_PLAYBOOK_DSN"].strip().replace("postgresql+asyncpg://", "postgresql://")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture(scope="module")
def agents(tmp_path_factory: pytest.TempPathFactory) -> Any:
    import httpx

    port = _free_port()
    env = {
        **os.environ,
        "DATABASE_URL": _dsn(),
        "AISOC_SERVICE_TOKEN": SERVICE_TOKEN,
        "SECRET_KEY": CONSOLE_SECRET,
        "ENVIRONMENT": "production",
        "PLAYBOOK_STORE_DIR": str(tmp_path_factory.mktemp("playbooks")),
        "AISOC_PLAYBOOK_SWEEP_INTERVAL_SECONDS": "1",
        "AISOC_HUNT_SCHEDULER_DISABLE": "1",
        "REALTIME_URL": f"http://127.0.0.1:{_free_port()}",
        "OTEL_SDK_DISABLED": "true",
        "PYTHONPATH": str(_AGENTS),
    }
    for name in ("AISOC_DEV_MODE", "AISOC_DEV_AUTH_BYPASS", "AISOC_AGENTS_SERVICE_TOKEN", "KAFKA_BOOTSTRAP_SERVERS"):
        env.pop(name, None)

    log_path = tmp_path_factory.mktemp("agents-log") / "agents.log"
    log = log_path.open("wb")
    proc = subprocess.Popen(
        [
            sys.executable,
            "-c",
            f"import uvicorn\nfrom app.main import app\nuvicorn.run(app, host='127.0.0.1', port={port}, log_level='warning')\n",
        ],
        cwd=str(_AGENTS),
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 60
    while time.time() < deadline:
        if proc.poll() is not None:
            log.close()
            pytest.fail(f"the agents service exited before serving:\n{log_path.read_text(errors='replace')[-3000:]}")
        try:
            if httpx.get(f"{base}/readyz", timeout=1.0).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        time.sleep(0.25)
    else:
        proc.terminate()
        log.close()
        pytest.fail(f"the agents service did not become ready within 60s:\n{log_path.read_text(errors='replace')[-3000:]}")

    yield base

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    log.close()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def db() -> AsyncIterator[Any]:
    asyncpg = pytest.importorskip("asyncpg")
    pool = await asyncpg.create_pool(_dsn(), min_size=1, max_size=4)
    yield pool
    await pool.close()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def api(agents: str) -> AsyncIterator[Any]:
    import httpx

    os.environ["DATABASE_URL"] = _dsn()
    os.environ["AISOC_SERVICE_TOKEN"] = SERVICE_TOKEN
    os.environ["SECRET_KEY"] = CONSOLE_SECRET
    os.environ["ENVIRONMENT"] = "production"
    os.environ["AGENTS_SERVICE_URL"] = agents
    os.environ["REALTIME_BASE_URL"] = f"http://127.0.0.1:{_free_port()}"
    for name in ("AISOC_DEV_MODE", "AISOC_DEV_AUTH_BYPASS", "AISOC_AGENTS_SERVICE_TOKEN"):
        os.environ.pop(name, None)

    from app.main import create_application

    transport = httpx.ASGITransport(app=create_application())
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def tenants(db: Any) -> AsyncIterator[dict[str, str]]:
    made: dict[str, str] = {}
    async with db.acquire() as conn:
        for label in ("owner", "stranger"):
            tenant_id = uuid.uuid4()
            user_id = uuid.uuid4()
            slug = f"approval-resume-{tenant_id.hex[:8]}"
            await conn.execute("INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)", tenant_id, slug)
            await conn.execute(
                "INSERT INTO users (id, tenant_id, email, username, hashed_password, role, is_active) "
                "VALUES ($1, $2, $3, $4, 'x', 'soc_analyst', true)",
                user_id,
                tenant_id,
                f"{slug}@example.com",
                slug,
            )
            made[label] = str(tenant_id)
            made[f"{label}_user"] = str(user_id)
    yield made
    async with db.acquire() as conn:
        await conn.execute("DELETE FROM tenants WHERE id = ANY($1::uuid[])", [made["owner"], made["stranger"]])


def _analyst(tenants: dict[str, str], label: str = "owner") -> dict[str, str]:
    from app.core.security import create_access_token

    token = create_access_token({"sub": tenants[f"{label}_user"], "tenant_id": tenants[label]})
    return {"Authorization": f"Bearer {token}"}


def _service(tenant: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {SERVICE_TOKEN}", TENANT_HEADER: tenant}


async def _poll(probe: Callable[[], Awaitable[Any]], *, seconds: float = 15.0) -> Any:
    deadline = time.monotonic() + seconds
    while True:
        value = await probe()
        if value or time.monotonic() > deadline:
            return value
        await asyncio.sleep(0.2)


async def _paused_run(agents: str, db: Any, tenant: str, **gate: Any) -> dict[str, Any]:
    import httpx

    playbook = {
        "name": "Contain after sign-off",
        "steps": [
            {"id": "gate", "name": "Analyst signs off", "type": "approval", "params": {"prompt": "Isolate WIN-FIN-02?", **gate}},
            {"id": "after", "name": "Runs only after sign-off", "type": "condition"},
        ],
    }
    async with httpx.AsyncClient(base_url=agents, headers=_service(tenant), timeout=10.0) as client:
        created = await client.post("/api/v1/playbooks", json=playbook)
        assert created.status_code == 201, created.text
        playbook_id = created.json()["id"]
        started = await client.post(f"/api/v1/playbooks/{playbook_id}/run", json={"context": {"host": "WIN-FIN-02"}})
        assert started.status_code == 202, started.text

    async def _row() -> Any:
        async with db.acquire() as conn:
            return await conn.fetchrow(
                "SELECT id, run_id, approval_id, status, expires_at FROM aisoc_playbook_pauses "
                "WHERE tenant_id = $1::uuid AND playbook_id = $2",
                tenant,
                playbook_id,
            )

    row = await _poll(_row)
    assert row is not None, "the run never paused at its approval step"
    assert row["approval_id"] is not None, "the run paused naming no approval, so no decision can ever reach it"
    return {**dict(row), "started_run_id": started.json()["run_id"]}


async def _pause_status(db: Any, pause: dict[str, Any]) -> str:
    async with db.acquire() as conn:
        return str(await conn.fetchval("SELECT status FROM aisoc_playbook_pauses WHERE id = $1", pause["id"]))


async def _run_record(agents: str, tenant: str, run_id: str) -> dict[str, Any] | None:
    import httpx

    async with httpx.AsyncClient(base_url=agents, headers=_service(tenant), timeout=10.0) as client:
        response = await client.get(f"/api/v1/playbooks/runs/{run_id}")
    return response.json() if response.status_code == 200 else None


async def _finished_run(agents: str, tenant: str, run_id: str) -> dict[str, Any] | None:
    async def _done() -> Any:
        run = await _run_record(agents, tenant, run_id)
        return run if run and run["status"] not in ("pending", "running", "paused") else None

    return await _poll(_done)


async def _decide(api: Any, tenants: dict[str, str], pause: dict[str, Any], decision: str) -> None:
    response = await api.post(
        f"/api/v1/approvals/{pause['approval_id']}/decide",
        json={"decision": decision, "comment": "checked the host"},
        headers=_analyst(tenants),
    )
    assert response.status_code == 200, f"{response.status_code}: {response.text[:300]}"


async def _resume_directly(agents: str, pause: dict[str, Any], headers: dict[str, str]) -> int:
    import httpx

    async with httpx.AsyncClient(base_url=agents, headers=headers, timeout=10.0) as client:
        response = await client.post(f"/api/v1/playbooks/approvals/{pause['approval_id']}/resume")
    return response.status_code


async def _past_the_deadline(pause: dict[str, Any], *, sweeps: int = 3) -> None:
    remaining = (pause["expires_at"] - datetime.now(UTC)).total_seconds()
    await asyncio.sleep(max(0.0, remaining) + sweeps)


class TestADecisionReachesTheRun:
    async def test_an_approved_run_continues_past_its_approval(self, api: Any, agents: str, db: Any, tenants: dict[str, str]) -> None:
        pause = await _paused_run(agents, db, tenants["owner"])

        await _decide(api, tenants, pause, "approve")

        run = await _finished_run(agents, tenants["owner"], pause["run_id"])
        assert run is not None, "the approval was recorded and the run never continued"
        assert run["status"] == "completed", json.dumps(run, default=str)[:600]
        assert [step["step_id"] for step in run["step_results"]][-1] == "after"
        assert await _pause_status(db, pause) == "resumed"

    async def test_the_run_its_caller_started_is_the_one_that_continues(
        self, api: Any, agents: str, db: Any, tenants: dict[str, str]
    ) -> None:
        pause = await _paused_run(agents, db, tenants["owner"])
        assert pause["run_id"] == pause["started_run_id"], "the run paused under an id its caller was never given"

        await _decide(api, tenants, pause, "approve")

        run = await _finished_run(agents, tenants["owner"], pause["started_run_id"])
        assert run is not None and run["status"] == "completed", "the run its caller polls never left paused"

    async def test_a_denied_run_does_not_continue(self, api: Any, agents: str, db: Any, tenants: dict[str, str]) -> None:
        pause = await _paused_run(agents, db, tenants["owner"])

        await _decide(api, tenants, pause, "deny")

        async def _denied() -> bool:
            return await _pause_status(db, pause) == "denied"

        assert await _poll(_denied), f"a denial left the pause {await _pause_status(db, pause)!r}"
        run = await _finished_run(agents, tenants["owner"], pause["started_run_id"])
        assert run is not None and run["status"] == "cancelled", "the run its caller polls still says it is waiting on a decision"
        assert "after" not in [step["step_id"] for step in run["step_results"]], "a denied run continued"


class TestTheSweeperLeavesADecidedPause:
    async def test_a_granted_approval_survives_its_deadline_and_resumes_on_retry(
        self,
        api: Any,
        agents: str,
        db: Any,
        tenants: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pause = await _paused_run(agents, db, tenants["owner"], expires_in_hours=DEADLINE_SECONDS / 3600)

        monkeypatch.setenv("AGENTS_SERVICE_URL", f"http://127.0.0.1:{_free_port()}")
        await _decide(api, tenants, pause, "approve")
        await _past_the_deadline(pause)
        assert await _pause_status(db, pause) == "waiting", "the sweeper expired a pause whose approval a human had granted"

        monkeypatch.setenv("AGENTS_SERVICE_URL", agents)
        await _decide(api, tenants, pause, "approve")

        run = await _finished_run(agents, tenants["owner"], pause["run_id"])
        assert run is not None and run["status"] == "completed", "a repeated approval did not deliver the decision"
        assert await _pause_status(db, pause) == "resumed"

    async def test_an_undecided_pause_still_expires(self, api: Any, agents: str, db: Any, tenants: dict[str, str]) -> None:
        pause = await _paused_run(agents, db, tenants["owner"], expires_in_hours=DEADLINE_SECONDS / 3600)

        await _past_the_deadline(pause)

        assert await _pause_status(db, pause) == "expired"


class TestOnlyTheApiServiceDeliversADecision:
    async def test_a_console_session_is_refused(self, api: Any, agents: str, db: Any, tenants: dict[str, str]) -> None:
        pause = await _paused_run(agents, db, tenants["owner"])

        assert await _resume_directly(agents, pause, _analyst(tenants)) == 403
        assert await _pause_status(db, pause) == "waiting"

    async def test_an_undecided_approval_does_not_resume_the_run(self, api: Any, agents: str, db: Any, tenants: dict[str, str]) -> None:
        pause = await _paused_run(agents, db, tenants["owner"])

        assert await _resume_directly(agents, pause, _service(tenants["owner"])) == 404
        await asyncio.sleep(1)
        assert await _pause_status(db, pause) == "waiting"

    async def test_another_tenant_cannot_deliver_it(
        self,
        api: Any,
        agents: str,
        db: Any,
        tenants: dict[str, str],
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        pause = await _paused_run(agents, db, tenants["owner"])
        monkeypatch.setenv("AGENTS_SERVICE_URL", f"http://127.0.0.1:{_free_port()}")
        await _decide(api, tenants, pause, "approve")

        assert await _resume_directly(agents, pause, _service(tenants["stranger"])) == 404
        await asyncio.sleep(1)
        assert await _pause_status(db, pause) == "waiting"

        assert await _resume_directly(agents, pause, _service(tenants["owner"])) == 202
        run = await _finished_run(agents, tenants["owner"], pause["run_id"])
        assert run is not None and run["status"] == "completed"
