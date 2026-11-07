from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
import threading
import time
import uuid
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import httpx
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
ANSWER_SECRET = "approval-resume-answer-secret-not-a-real-secret"
TENANT_HEADER = "X-AiSOC-Tenant-ID"
DEADLINE_SECONDS = 4
HOLD_SECONDS = 2
AGENTS_APPLICATION = f"approval-resume-agents-{uuid.uuid4().hex[:12]}"

_AGENTS = Path(__file__).resolve().parents[2] / "services" / "agents"


def _dsn() -> str:
    return os.environ["ISOLATION_PLAYBOOK_DSN"].strip().replace("postgresql+asyncpg://", "postgresql://")


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class _Realtime:
    def __init__(self) -> None:
        self.url = ""
        self.playbook_id = ""
        self.step_id = ""
        self.reached = threading.Event()
        self.release = threading.Event()
        self.dispatched: list[dict[str, Any]] = []

    def hold(self, playbook_id: str, step_id: str) -> None:
        self.reached.clear()
        self.release.clear()
        self.playbook_id = playbook_id
        self.step_id = step_id

    def answer(self, handler: BaseHTTPRequestHandler) -> None:
        event = json.loads(handler.rfile.read(int(handler.headers.get("Content-Length") or 0)) or b"{}")
        if handler.path == "/api/v1/playbook-steps/dispatch":
            # The API's governed dispatch too, answering as it does while
            # action execution is off: the notify was previewed, not sent.
            self.dispatched.append(event)
            report = {"executed": False, "status": "dry_run", "summary": "DRY RUN — 'notify' was previewed and nothing was changed."}
            body = json.dumps(report).encode()
            handler.send_response(200)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)
            return
        data = event.get("data") or {}
        held = (
            event.get("type") == "run.done"
            and data.get("status") == "paused"
            and data.get("playbook_id") == self.playbook_id
            and (data.get("step_results") or [{}])[-1].get("step_id") == self.step_id
            and not self.reached.is_set()
        )
        handler.send_response(200)
        if not held:
            handler.send_header("Content-Length", "0")
            handler.end_headers()
            return
        handler.send_header("Transfer-Encoding", "chunked")
        handler.end_headers()
        self.reached.set()
        # The engine posts with a 3 second read timeout. A byte every half
        # second keeps the starter parked until the test releases it.
        while not self.release.wait(0.5):
            handler.wfile.write(b"1\r\n \r\n")
            handler.wfile.flush()
        handler.wfile.write(b"0\r\n\r\n")
        handler.wfile.flush()


@pytest.fixture(scope="module")
def realtime() -> Iterator[_Realtime]:
    stand_in = _Realtime()

    class _Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_POST(self) -> None:
            stand_in.answer(self)

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    stand_in.url = f"http://127.0.0.1:{server.server_address[1]}"
    yield stand_in
    stand_in.release.set()
    server.shutdown()


@pytest.fixture(scope="module")
def agents(tmp_path_factory: pytest.TempPathFactory, realtime: _Realtime) -> Any:
    port = _free_port()
    env = {
        **os.environ,
        "DATABASE_URL": f"{_dsn()}{'&' if '?' in _dsn() else '?'}application_name={AGENTS_APPLICATION}",
        "AISOC_SERVICE_TOKEN": SERVICE_TOKEN,
        "SECRET_KEY": CONSOLE_SECRET,
        "ENVIRONMENT": "production",
        "PLAYBOOK_STORE_DIR": str(tmp_path_factory.mktemp("playbooks")),
        "AISOC_PLAYBOOK_SWEEP_INTERVAL_SECONDS": "1",
        "AISOC_HUNT_SCHEDULER_DISABLE": "1",
        "AISOC_PLAYBOOK_VERIFY_EXECUTE": "1",
        "AISOC_CHATOPS_RESPONSE_SECRET": ANSWER_SECRET,
        "AISOC_AGENTS_SERVICE_TOKEN": SERVICE_TOKEN,
        "API_SERVICE_URL": realtime.url,
        "REALTIME_URL": realtime.url,
        "OTEL_SDK_DISABLED": "true",
        "PYTHONPATH": str(_AGENTS),
    }
    for name in ("AISOC_DEV_MODE", "AISOC_DEV_AUTH_BYPASS", "KAFKA_BOOTSTRAP_SERVERS"):
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


async def _paused_run(
    agents: str,
    db: Any,
    tenant: str,
    *,
    gates: tuple[str, ...] = ("gate",),
    held_by: _Realtime | None = None,
    held_at: str = "gate",
    after: dict[str, Any] | None = None,
    callback_first: bool = False,
    **gate: Any,
) -> dict[str, Any]:
    playbook_id, run_id = await _started_run(
        agents, db, tenant, gates=gates, held_by=held_by, held_at=held_at, after=after, callback_first=callback_first, **gate
    )
    pause = await _pause_at(db, tenant, playbook_id, gates[0])
    return {**pause, "playbook_id": playbook_id, "started_run_id": run_id}


async def _started_run(
    agents: str,
    db: Any,
    tenant: str,
    *,
    gates: tuple[str, ...] = ("gate",),
    held_by: _Realtime | None = None,
    held_at: str = "gate",
    after: dict[str, Any] | None = None,
    callback_first: bool = False,
    **gate: Any,
) -> tuple[str, str]:
    playbook = {
        "name": "Contain after sign-off",
        "steps": [
            *(
                [{"id": "callback", "name": "Waits for the scanner", "type": "wait", "params": {"until": "callback"}}]
                if callback_first
                else []
            ),
            *(
                {"id": step_id, "name": "Analyst signs off", "type": "approval", "params": {"prompt": "Isolate WIN-FIN-02?", **gate}}
                for step_id in gates
            ),
            {"id": "after", "name": "Runs only after sign-off", "type": "condition", **(after or {})},
        ],
    }
    async with httpx.AsyncClient(base_url=agents, headers=_service(tenant), timeout=10.0) as client:
        created = await client.post("/api/v1/playbooks", json=playbook)
        assert created.status_code == 201, created.text
        playbook_id = created.json()["id"]
        if held_by is not None:
            held_by.hold(playbook_id, held_at)
        started = await client.post(f"/api/v1/playbooks/{playbook_id}/run", json={"context": {"host": "WIN-FIN-02"}})
        assert started.status_code == 202, started.text
        if callback_first:
            resumed = await client.post(f"/api/v1/playbook-waits/{await _resume_token(db, tenant, playbook_id, 'callback')}/resume")
            assert resumed.status_code == 202, resumed.text
    return playbook_id, str(started.json()["run_id"])


async def _resume_token(db: Any, tenant: str, playbook_id: str, step_id: str) -> str:
    async def _token() -> Any:
        async with db.acquire() as conn:
            return await conn.fetchval(
                "SELECT resume_token FROM aisoc_playbook_pauses WHERE tenant_id = $1::uuid AND playbook_id = $2 AND step_id = $3",
                tenant,
                playbook_id,
                step_id,
            )

    token = await _poll(_token)
    assert token, f"the run never suspended at {step_id!r}"
    return str(token)


async def _pause_at(db: Any, tenant: str, playbook_id: str, step_id: str) -> dict[str, Any]:
    async def _row() -> Any:
        async with db.acquire() as conn:
            return await conn.fetchrow(
                "SELECT id, run_id, approval_id, status, expires_at FROM aisoc_playbook_pauses "
                "WHERE tenant_id = $1::uuid AND playbook_id = $2 AND step_id = $3",
                tenant,
                playbook_id,
                step_id,
            )

    row = await _poll(_row)
    assert row is not None, f"the run never paused at its {step_id!r} approval step"
    assert row["approval_id"] is not None, "the run paused naming no approval, so no decision can ever reach it"
    return dict(row)


async def _pause_status(db: Any, pause: dict[str, Any]) -> str:
    async with db.acquire() as conn:
        return str(await conn.fetchval("SELECT status FROM aisoc_playbook_pauses WHERE id = $1", pause["id"]))


async def _run_record(agents: str, tenant: str, run_id: str) -> dict[str, Any] | None:
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

    async def test_a_step_gated_on_its_approval_runs(self, api: Any, agents: str, db: Any, tenants: dict[str, str]) -> None:
        owner = tenants["owner"]
        first = await _paused_run(agents, db, owner, gates=("gate", "second"), after={"condition": "steps.gate.outcome == 'approved'"})

        await _decide(api, tenants, first, "approve")
        await _decide(api, tenants, await _pause_at(db, owner, first["playbook_id"], "second"), "approve")

        run = await _finished_run(agents, owner, first["run_id"])
        assert run is not None, "both approvals were recorded and the run never finished"
        gated = {step["step_id"]: step["status"] for step in run["step_results"]}.get("after")
        assert gated == "success", f"both approvals were granted and the step gated on the first reads {gated}"

    async def test_its_completed_record_names_the_approval_and_who_decided_it(
        self, api: Any, agents: str, db: Any, tenants: dict[str, str]
    ) -> None:
        pause = await _paused_run(agents, db, tenants["owner"])

        await _decide(api, tenants, pause, "approve")

        run = await _finished_run(agents, tenants["owner"], pause["run_id"])
        assert run is not None and run["status"] == "completed", f"the approved run reads {run and run['status']}"
        listed = [step["step_id"] for step in run["step_results"]]
        assert listed == ["gate", "after"], f"the completed record lists {listed}"
        gate = run["step_results"][0]
        assert gate["status"] == "success", gate
        assert gate["result"]["decided_by"] == tenants["owner_user"], gate

    async def test_the_run_its_caller_started_is_the_one_that_continues(
        self, api: Any, agents: str, db: Any, tenants: dict[str, str]
    ) -> None:
        pause = await _paused_run(agents, db, tenants["owner"])
        assert pause["run_id"] == pause["started_run_id"], "the run paused under an id its caller was never given"

        async def _paused() -> Any:
            run = await _run_record(agents, tenants["owner"], pause["started_run_id"])
            return run if run and run["status"] == "paused" else None

        assert await _poll(_paused), "the run its caller polls never said it was waiting on its approval"
        await _decide(api, tenants, pause, "approve")

        run = await _finished_run(agents, tenants["owner"], pause["started_run_id"])
        assert run is not None and run["status"] == "completed", "the run its caller polls never left paused"

    async def test_its_actions_name_the_run_its_caller_was_given(
        self, api: Any, agents: str, db: Any, tenants: dict[str, str], realtime: _Realtime
    ) -> None:
        owner = tenants["owner"]
        block = {"type": "block_ip", "params": {"ip": "203.0.113.7"}, "on_failure": "continue"}
        playbook = {
            "name": "Block either side of a sign-off",
            "steps": [
                {"id": "before", "name": "Blocks before sign-off", **block},
                {"id": "gate", "name": "Analyst signs off", "type": "approval", "params": {"prompt": "Block it again?"}},
                {"id": "after", "name": "Blocks after sign-off", **block},
            ],
        }
        seen = len(realtime.dispatched)
        async with httpx.AsyncClient(base_url=agents, headers=_service(owner), timeout=10.0) as client:
            created = await client.post("/api/v1/playbooks", json=playbook)
            assert created.status_code == 201, created.text
            playbook_id = created.json()["id"]
            started = await client.post(f"/api/v1/playbooks/{playbook_id}/run", json={"context": {}})
        assert started.status_code == 202, started.text
        run_id = str(started.json()["run_id"])

        await _decide(api, tenants, await _pause_at(db, owner, playbook_id, "gate"), "approve")

        assert await _finished_run(agents, owner, run_id) is not None, "the approval was recorded and the run never finished"
        named = {call["playbook_step_id"]: call["playbook_run_id"] for call in realtime.dispatched[seen:]}
        assert named == {"before": run_id, "after": run_id}, f"the run is {run_id} and its actions name {named}"

    async def test_a_denied_run_does_not_continue(self, api: Any, agents: str, db: Any, tenants: dict[str, str]) -> None:
        pause = await _paused_run(agents, db, tenants["owner"])

        await _decide(api, tenants, pause, "deny")

        async def _denied() -> bool:
            return await _pause_status(db, pause) == "denied"

        assert await _poll(_denied), f"a denial left the pause {await _pause_status(db, pause)!r}"
        run = await _finished_run(agents, tenants["owner"], pause["started_run_id"])
        assert run is not None and run["status"] == "cancelled", "the run its caller polls still says it is waiting on a decision"
        assert "after" not in [step["step_id"] for step in run["step_results"]], "a denied run continued"


async def _decided_while_held(
    api: Any, agents: str, tenants: dict[str, str], realtime: _Realtime, run_id: str, pause: dict[str, Any], decision: str
) -> tuple[str, str]:
    assert await asyncio.to_thread(realtime.reached.wait, 10), "the held leg never reached the end of its run"

    await _decide(api, tenants, pause, decision)
    await _finished_run(agents, tenants["owner"], run_id)
    decided = await _run_record(agents, tenants["owner"], run_id)
    realtime.release.set()
    await asyncio.sleep(1)

    run = await _run_record(agents, tenants["owner"], run_id)
    assert decided is not None and run is not None
    return str(decided["status"]), str(run["status"])


async def _kept_its_later_pause(
    api: Any, agents: str, db: Any, tenants: dict[str, str], realtime: _Realtime, first: dict[str, Any], held: dict[str, Any], later: str
) -> None:
    owner = tenants["owner"]
    assert await asyncio.to_thread(realtime.reached.wait, 10), "the held leg never reached the end of its run"
    await _decide(api, tenants, held, "approve")
    pause = await _pause_at(db, owner, first["playbook_id"], later)

    async def _paused_again() -> Any:
        run = await _run_record(agents, owner, first["started_run_id"])
        return run if run and later in [step["step_id"] for step in run["step_results"]] else None

    assert await _poll(_paused_again), f"the resumed run never recorded its pause at {later!r}"
    realtime.release.set()
    await asyncio.sleep(1)

    run = await _run_record(agents, owner, first["started_run_id"])
    assert run is not None
    steps = [step["step_id"] for step in run["step_results"]]
    assert run["status"] == "paused" and steps[-1] == later, f"an earlier leg's snapshot replaced a later one: {run['status']} at {steps}"
    await _decide(api, tenants, pause, "approve")
    finished = await _finished_run(agents, owner, first["started_run_id"])
    assert finished is not None and finished["status"] == "completed"


class TestTheStarterCannotUndoADecision:
    async def test_an_approval_that_finishes_first_stays_completed(
        self, api: Any, agents: str, db: Any, tenants: dict[str, str], realtime: _Realtime
    ) -> None:
        pause = await _paused_run(agents, db, tenants["owner"], held_by=realtime)
        before, after = await _decided_while_held(api, agents, tenants, realtime, pause["started_run_id"], pause, "approve")
        assert after == "completed", f"the starter's paused snapshot replaced the finished run: {before} then {after}"

    async def test_a_denial_that_lands_first_stays_cancelled(
        self, api: Any, agents: str, db: Any, tenants: dict[str, str], realtime: _Realtime
    ) -> None:
        pause = await _paused_run(agents, db, tenants["owner"], held_by=realtime)
        before, after = await _decided_while_held(api, agents, tenants, realtime, pause["started_run_id"], pause, "deny")
        assert after == "cancelled", f"the starter's paused snapshot replaced the denied run: {before} then {after}"

    async def test_a_run_that_paused_again_keeps_its_later_pause(
        self, api: Any, agents: str, db: Any, tenants: dict[str, str], realtime: _Realtime
    ) -> None:
        first = await _paused_run(agents, db, tenants["owner"], gates=("gate", "second"), held_by=realtime)
        await _kept_its_later_pause(api, agents, db, tenants, realtime, first, first, "second")


class TestAnEarlierResumeCannotUndoALaterDecision:
    async def _second_gate_held(
        self,
        api: Any,
        agents: str,
        db: Any,
        tenants: dict[str, str],
        realtime: _Realtime,
        gates: tuple[str, ...] = ("gate", "second"),
        **after: Any,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        first = await _paused_run(agents, db, tenants["owner"], gates=gates, held_by=realtime, held_at="second", after=after)
        await _decide(api, tenants, first, "approve")
        return first, await _pause_at(db, tenants["owner"], first["playbook_id"], "second")

    async def test_a_second_approval_that_finishes_first_stays_completed(
        self, api: Any, agents: str, db: Any, tenants: dict[str, str], realtime: _Realtime
    ) -> None:
        first, second = await self._second_gate_held(api, agents, db, tenants, realtime)
        before, after = await _decided_while_held(api, agents, tenants, realtime, first["started_run_id"], second, "approve")
        assert after == "completed", f"the first resume's paused snapshot replaced the finished run: {before} then {after}"

    async def test_a_second_denial_that_lands_first_stays_cancelled(
        self, api: Any, agents: str, db: Any, tenants: dict[str, str], realtime: _Realtime
    ) -> None:
        first, second = await self._second_gate_held(api, agents, db, tenants, realtime)
        before, after = await _decided_while_held(api, agents, tenants, realtime, first["started_run_id"], second, "deny")
        assert after == "cancelled", f"the first resume's paused snapshot replaced the denied run: {before} then {after}"

    async def test_a_second_leg_that_fails_first_stays_failed(
        self, api: Any, agents: str, db: Any, tenants: dict[str, str], realtime: _Realtime
    ) -> None:
        first, second = await self._second_gate_held(api, agents, db, tenants, realtime, next_true="gate")
        before, after = await _decided_while_held(api, agents, tenants, realtime, first["started_run_id"], second, "approve")
        assert before == "failed", f"looping back to an approval that already ran should fail the run, not {before}"
        assert after == "failed", f"the first resume's paused snapshot replaced the failed run: {before} then {after}"

    async def test_a_second_leg_that_paused_again_keeps_its_later_pause(
        self, api: Any, agents: str, db: Any, tenants: dict[str, str], realtime: _Realtime
    ) -> None:
        first, second = await self._second_gate_held(api, agents, db, tenants, realtime, gates=("gate", "second", "third"))
        await _kept_its_later_pause(api, agents, db, tenants, realtime, first, second, "third")

    async def test_a_callback_resume_cannot_undo_the_pause_after_it(
        self, api: Any, agents: str, db: Any, tenants: dict[str, str], realtime: _Realtime
    ) -> None:
        first = await _paused_run(agents, db, tenants["owner"], gates=("gate", "second"), held_by=realtime, callback_first=True)
        await _kept_its_later_pause(api, agents, db, tenants, realtime, first, first, "second")

    async def _answer_held_at_gate(
        self, api: Any, agents: str, db: Any, tenants: dict[str, str], realtime: _Realtime, decision: str
    ) -> tuple[str, str]:
        unsent = await _unsent_verification(agents, db, tenants["owner"], gates=("gate",))
        realtime.hold(unsent["playbook_id"], "gate")
        answering = asyncio.create_task(_answer(agents, unsent["token"]))
        gate = await _pause_at(db, tenants["owner"], unsent["playbook_id"], "gate")
        decided = await _decided_while_held(api, agents, tenants, realtime, unsent["run_id"], gate, decision)
        assert await answering == 200
        return decided

    async def test_an_answered_verification_cannot_undo_the_approval_after_it(
        self, api: Any, agents: str, db: Any, tenants: dict[str, str], realtime: _Realtime
    ) -> None:
        before, after = await self._answer_held_at_gate(api, agents, db, tenants, realtime, "approve")
        assert after == "completed", f"the answer's paused snapshot replaced the finished run: {before} then {after}"

    async def test_an_answered_verification_cannot_undo_the_denial_after_it(
        self, api: Any, agents: str, db: Any, tenants: dict[str, str], realtime: _Realtime
    ) -> None:
        before, after = await self._answer_held_at_gate(api, agents, db, tenants, realtime, "deny")
        assert after == "cancelled", f"the answer's paused snapshot replaced the denied run: {before} then {after}"


async def _unsent_verification(agents: str, db: Any, tenant: str, *, gates: tuple[str, ...] = ()) -> dict[str, str]:
    playbook = {
        "name": "Ask the account holder",
        "steps": [
            {"id": "verify", "name": "Was this you?", "type": "verify_user", "params": {"user": "j.doe@example.com"}},
            *(
                {"id": step_id, "name": "Analyst signs off", "type": "approval", "params": {"prompt": "Lock the account?"}}
                for step_id in gates
            ),
            {"id": "after", "name": "Runs after the answer", "type": "condition"},
        ],
    }
    async with httpx.AsyncClient(base_url=agents, headers=_service(tenant), timeout=10.0) as client:
        created = await client.post("/api/v1/playbooks", json=playbook)
        assert created.status_code == 201, created.text
        playbook_id = created.json()["id"]
        started = await client.post(f"/api/v1/playbooks/{playbook_id}/run", json={"context": {"initiated_by_human": True}})
        assert started.status_code == 202, started.text
    run_id = started.json()["run_id"]

    failed = await _finished_run(agents, tenant, run_id)
    assert failed is not None and failed["status"] == "failed", f"the unsent prompt left the run {failed and failed['status']}"
    return {"playbook_id": playbook_id, "run_id": run_id, "token": await _resume_token(db, tenant, playbook_id, "verify")}


async def _answer(agents: str, token: str) -> int:
    signature = hmac.new(ANSWER_SECRET.encode(), f"{token}|acknowledged|user".encode(), hashlib.sha256).hexdigest()
    async with httpx.AsyncClient(base_url=agents, timeout=60.0) as client:
        response = await client.get(f"/api/v1/playbook-verifications/{token}/acknowledged", params={"sig": signature})
    return response.status_code


class TestALaterLegReplacesAFailedRecord:
    async def test_an_answer_to_a_prompt_that_was_not_sent_still_finishes_the_run(
        self, agents: str, db: Any, tenants: dict[str, str]
    ) -> None:
        unsent = await _unsent_verification(agents, db, tenants["owner"])

        assert await _answer(agents, unsent["token"]) == 200

        run = await _run_record(agents, tenants["owner"], unsent["run_id"])
        assert run is not None and run["status"] == "completed", f"the answered run still reads {run and run['status']}"


class TestADenialCancelsOnlyTheRunItStopped:
    async def test_a_denial_whose_pause_already_resumed_cancels_nothing(
        self, api: Any, agents: str, db: Any, tenants: dict[str, str]
    ) -> None:
        owner = tenants["owner"]
        first = await _paused_run(agents, db, owner, gates=("gate", "second"))
        await _decide(api, tenants, first, "approve")
        second = await _pause_at(db, owner, first["playbook_id"], "second")

        async def _at_second() -> Any:
            run = await _run_record(agents, owner, first["started_run_id"])
            return run if run and run["status"] == "paused" and run["step_results"][-1]["step_id"] == "second" else None

        assert await _poll(_at_second), "the approved run never recorded its second pause"
        async with db.acquire() as conn:
            await conn.execute("UPDATE agent_approvals SET status = 'denied' WHERE id = $1", first["approval_id"])
        assert await _resume_directly(agents, first, _service(owner)) == 202
        await asyncio.sleep(1)

        run = await _run_record(agents, owner, first["started_run_id"])
        assert run is not None and run["status"] == "paused", f"a denial its pause never saw cancelled the run: {run and run['status']}"
        await _decide(api, tenants, second, "approve")
        finished = await _finished_run(agents, owner, first["started_run_id"])
        assert finished is not None and finished["status"] == "completed", f"the run finished but reads {finished and finished['status']}"


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


async def _blocked_at_pause_write(db: Any) -> None:
    async def _waiting() -> Any:
        async with db.acquire() as conn:
            return await conn.fetchval(
                "SELECT count(*) FROM pg_stat_activity WHERE application_name = $1 "
                "AND wait_event_type = 'Lock' AND query LIKE '%INSERT INTO aisoc_playbook_pauses%'",
                AGENTS_APPLICATION,
            )

    assert await _poll(_waiting), "the run never reached its pause write"


async def _decide_once_open(api: Any, db: Any, tenants: dict[str, str], run_id: str, decision: str) -> None:
    async def _approval() -> Any:
        async with db.acquire() as conn:
            return await conn.fetchval(
                "SELECT id FROM agent_approvals WHERE tenant_id = $1::uuid AND action->>'run_id' = $2",
                tenants["owner"],
                run_id,
            )

    approval_id = await _poll(_approval)
    assert approval_id is not None, "the run never opened its approval"
    await _decide(api, tenants, {"approval_id": approval_id}, decision)


class TestADecisionBeforeItsPauseIsWritten:
    async def _decided_while_the_pause_write_waits(
        self, api: Any, agents: str, db: Any, tenants: dict[str, str], decision: str
    ) -> tuple[dict[str, Any] | None, str]:
        owner = tenants["owner"]
        async with db.acquire() as locker, locker.transaction():
            # SHARE blocks the pause INSERT and no read, so the run stops at its
            # pause write for as long as this transaction is open.
            await locker.execute("LOCK TABLE aisoc_playbook_pauses IN SHARE MODE")
            playbook_id, run_id = await _started_run(agents, db, owner, expires_in_hours=(HOLD_SECONDS + DEADLINE_SECONDS) / 3600)
            await _blocked_at_pause_write(db)
            deciding = asyncio.create_task(_decide_once_open(api, db, tenants, run_id, decision))
            await asyncio.sleep(HOLD_SECONDS)
        await deciding

        await _finished_run(agents, owner, run_id)
        run = await _run_record(agents, owner, run_id)
        pause = await _pause_at(db, owner, playbook_id, "gate")
        return run, str(pause["status"])

    async def test_an_approval_decided_as_it_opens_continues_the_run(self, api: Any, agents: str, db: Any, tenants: dict[str, str]) -> None:
        run, pause = await self._decided_while_the_pause_write_waits(api, agents, db, tenants, "approve")

        assert run is not None and run["status"] == "completed", (
            f"the approval was recorded and the run reads {run and run['status']}; its pause is {pause}"
        )
        assert [step["step_id"] for step in run["step_results"]][-1] == "after"
        assert pause == "resumed"

    async def test_a_denial_decided_as_it_opens_cancels_the_run(self, api: Any, agents: str, db: Any, tenants: dict[str, str]) -> None:
        run, pause = await self._decided_while_the_pause_write_waits(api, agents, db, tenants, "deny")

        assert run is not None and run["status"] == "cancelled", (
            f"the denial was recorded and the run reads {run and run['status']}; its pause is {pause}"
        )
        assert "after" not in [step["step_id"] for step in run["step_results"]], "a denied run continued"
        assert pause == "denied"


class TestAPlaybookDeletedWhileItsRunWaits:
    async def test_an_approval_after_the_delete_fails_the_run(self, api: Any, agents: str, db: Any, tenants: dict[str, str]) -> None:
        owner = tenants["owner"]
        pause = await _paused_run(agents, db, owner)
        async with httpx.AsyncClient(base_url=agents, headers=_service(owner), timeout=10.0) as client:
            deleted = await client.delete(f"/api/v1/playbooks/{pause['playbook_id']}")
        assert deleted.status_code == 204, deleted.text

        await _decide(api, tenants, pause, "approve")

        await _finished_run(agents, owner, pause["run_id"])
        run = await _run_record(agents, owner, pause["run_id"])
        status = await _pause_status(db, pause)
        assert run is not None and run["status"] == "failed", (
            f"the approval was recorded and the run reads {run and run['status']}; its pause is {status}"
        )
        assert status == "cancelled"


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
