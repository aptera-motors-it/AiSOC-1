from __future__ import annotations

import asyncio
import json
import threading
import time
import urllib.parse
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from app.core.config import get_settings
from app.main import app
from httpx import ASGITransport, AsyncClient
from slack_sdk.web.async_client import AsyncWebClient
from slack_sdk.web.async_slack_response import AsyncSlackResponse

TOKEN = "internal-secret"
ACTION_ID = "act-timeout-1"
_slack_posts: list[object] = []

CARD = {
    "action": {
        "id": ACTION_ID,
        "action_type": "isolate_host",
        "target": "WKSTN-01",
        "risk_level": "high",
        "rationale": "Confirmed beacon.",
    },
    "case": {"id": "case-9", "title": "Beaconing on WKSTN-01"},
    "timeout_seconds": 1,
}


class _Actions(BaseHTTPRequestHandler):
    received: list[tuple[str, bytes]] = []
    hold_approve_seconds: float = 0
    approve_status: int = 200
    approve_entered: threading.Event | None = None
    release_approve: threading.Event | None = None
    approve_done: threading.Event | None = None
    reject_entered: threading.Event | None = None
    release_reject: threading.Event | None = None

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler method name
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        type(self).received.append((self.path, body))
        if self.path.endswith("/approve"):
            entered = type(self).approve_entered
            if entered is not None:
                entered.set()
            release = type(self).release_approve
            if release is not None:
                release.wait(5)
            elif type(self).hold_approve_seconds > 0:
                time.sleep(type(self).hold_approve_seconds)
        elif self.path.endswith("/reject"):
            entered = type(self).reject_entered
            if entered is not None:
                entered.set()
            release = type(self).release_reject
            if release is not None:
                release.wait(5)
        status_code = type(self).approve_status if self.path.endswith("/approve") else 200
        payload = json.dumps({"id": ACTION_ID, "status": "ok"}).encode()
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        if self.path.endswith("/approve"):
            done = type(self).approve_done
            if done is not None:
                done.set()

    def log_message(self, format: str, *args: object) -> None:
        return


@pytest.fixture
def actions_url(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    _Actions.received = []
    _Actions.hold_approve_seconds = 0
    _Actions.approve_status = 200
    _Actions.approve_entered = None
    _Actions.release_approve = None
    _Actions.approve_done = None
    _Actions.reject_entered = None
    _Actions.release_reject = None
    _slack_posts.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Actions)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    monkeypatch.setenv("AISOC_ACTIONS_BASE_URL", base)
    monkeypatch.setenv("AISOC_ACTIONS_SERVICE_TOKEN", "actions-token")
    monkeypatch.setenv("AISOC_INTERNAL_TOKEN", TOKEN)
    monkeypatch.setenv("SLACK_APPROVALS_CHANNEL", "#soc-approvals")
    monkeypatch.setenv("SLACK_BOT_TOKEN", "xoxb-test")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("SLACK_SIGNING_SECRET", raising=False)
    get_settings.cache_clear()

    async def chat_post_message(self: AsyncWebClient, **kwargs: object) -> dict[str, object]:
        _slack_posts.append(kwargs.get("channel"))
        return {"ok": True, "ts": "1700000000.000100", "channel": kwargs.get("channel")}

    async def auth_test(self: AsyncWebClient, **kwargs: object) -> AsyncSlackResponse:
        data = {
            "ok": True,
            "team_id": "T1",
            "user_id": "UBOT",
            "bot_id": "B1",
            "enterprise_id": None,
            "is_enterprise_install": False,
        }
        return AsyncSlackResponse(
            client=self,
            http_verb="POST",
            api_url="auth.test",
            req_args=kwargs,
            data=data,
            headers={},
            status_code=200,
        )

    monkeypatch.setattr(AsyncWebClient, "chat_postMessage", chat_post_message)
    monkeypatch.setattr(AsyncWebClient, "auth_test", auth_test)
    yield base
    server.shutdown()
    server.server_close()
    get_settings.cache_clear()


def _reject_bodies() -> list[bytes]:
    return [body for path, body in _Actions.received if path == f"/api/v1/actions/{ACTION_ID}/reject"]


async def _post_card(client: AsyncClient) -> None:
    response = await client.post(
        "/internal/approval-card",
        json=CARD,
        headers={"X-AiSOC-Internal-Token": TOKEN},
    )
    assert response.status_code == 202
    assert response.json()["posted"] is True


@pytest.mark.asyncio
@pytest.mark.usefixtures("actions_url")
async def test_an_undecided_approval_card_is_rejected_when_its_deadline_passes() -> None:
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://bot") as client:
            await _post_card(client)
            await asyncio.sleep(0.2)
            assert _reject_bodies() == []
            deadline = asyncio.get_running_loop().time() + 5
            while asyncio.get_running_loop().time() < deadline and not _reject_bodies():
                await asyncio.sleep(0.05)

    assert _reject_bodies() == [b""]


def _click(slack_action_id: str) -> str:
    payload = {
        "type": "block_actions",
        "user": {"id": "U-SOC-LEAD"},
        "channel": {"id": "C-SOC"},
        "team": {"id": "T1"},
        "actions": [{"action_id": slack_action_id, "value": f"{ACTION_ID}|case-9", "type": "button"}],
        "response_url": "http://127.0.0.1:9/never",
        "trigger_id": "1.2.3",
    }
    return urllib.parse.urlencode({"payload": json.dumps(payload)})


@pytest.mark.asyncio
@pytest.mark.usefixtures("actions_url")
async def test_a_decision_before_the_deadline_is_not_followed_by_the_timeout() -> None:
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://bot") as client:
            await _post_card(client)
            click = await client.post(
                "/slack/events",
                content=_click("aisoc_action_deny"),
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
            assert click.status_code == 200
            await asyncio.sleep(1.5)

    bodies = _reject_bodies()
    assert len(bodies) == 1
    assert json.loads(bodies[0])["chatops_approver"]["platform_user_id"] == "U-SOC-LEAD"


def _paths() -> list[str]:
    return [path for path, _ in _Actions.received]


@pytest.mark.asyncio
@pytest.mark.usefixtures("actions_url")
async def test_a_slow_approve_before_the_deadline_is_not_also_rejected() -> None:
    _Actions.hold_approve_seconds = 0.8
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://bot") as client:
            await _post_card(client)
            await asyncio.sleep(0.6)
            click = await client.post(
                "/slack/events",
                content=_click("aisoc_action_approve"),
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
            assert click.status_code == 200
            await asyncio.sleep(1.1)

    assert _paths() == [f"/api/v1/actions/{ACTION_ID}/approve"]
    assert json.loads(_Actions.received[0][1])["chatops_approver"]["platform_user_id"] == "U-SOC-LEAD"


@pytest.mark.asyncio
@pytest.mark.usefixtures("actions_url")
async def test_a_failed_approve_still_rejects_when_the_deadline_passes() -> None:
    _Actions.approve_status = 500
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://bot") as client:
            await _post_card(client)
            click = await client.post(
                "/slack/events",
                content=_click("aisoc_action_approve"),
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
            assert click.status_code == 200
            deadline = asyncio.get_running_loop().time() + 5
            while asyncio.get_running_loop().time() < deadline and not _reject_bodies():
                await asyncio.sleep(0.05)

    assert f"/api/v1/actions/{ACTION_ID}/approve" in _paths()
    assert _reject_bodies() == [b""]


@pytest.mark.asyncio
@pytest.mark.usefixtures("actions_url")
async def test_need_info_leaves_the_deadline_armed() -> None:
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://bot") as client:
            await _post_card(client)
            click = await client.post(
                "/slack/events",
                content=_click("aisoc_action_need_info"),
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
            assert click.status_code == 200
            deadline = asyncio.get_running_loop().time() + 5
            while asyncio.get_running_loop().time() < deadline and not _reject_bodies():
                await asyncio.sleep(0.05)

    assert _paths() == [f"/api/v1/actions/{ACTION_ID}/reject"]
    assert _reject_bodies() == [b""]


@pytest.mark.asyncio
@pytest.mark.usefixtures("actions_url")
async def test_the_timer_row_stays_until_the_approve_replaces_the_card() -> None:
    entered = threading.Event()
    release = threading.Event()
    _Actions.approve_entered = entered
    _Actions.release_approve = release
    card = {**CARD, "timeout_seconds": 60}
    try:
        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://bot") as client:
                posted = await client.post(
                    "/internal/approval-card",
                    json=card,
                    headers={"X-AiSOC-Internal-Token": TOKEN},
                )
                assert posted.status_code == 202
                await asyncio.sleep(0)
                store = app.state.timeout_scheduler._store
                assert [row.action_id for row in await store.list_pending()] == [ACTION_ID]
                click_task = asyncio.create_task(
                    client.post(
                        "/slack/events",
                        content=_click("aisoc_action_approve"),
                        headers={"content-type": "application/x-www-form-urlencoded"},
                    )
                )
                assert await asyncio.to_thread(entered.wait, 5)
                await asyncio.sleep(0)
                assert [row.action_id for row in await store.list_pending()] == [ACTION_ID]
                release.set()
                click = await click_task
                assert click.status_code == 200
                await asyncio.sleep(0)
                assert await store.list_pending() == []
    finally:
        release.set()


@pytest.mark.asyncio
@pytest.mark.usefixtures("actions_url")
async def test_the_click_that_replaces_the_card_deletes_the_row_another_click_suspended() -> None:
    entered = threading.Event()
    release = threading.Event()
    approve_done = threading.Event()
    _Actions.approve_entered = entered
    _Actions.release_approve = release
    _Actions.approve_done = approve_done
    card = {**CARD, "timeout_seconds": 60}
    try:
        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://bot") as client:
                posted = await client.post(
                    "/internal/approval-card",
                    json=card,
                    headers={"X-AiSOC-Internal-Token": TOKEN},
                )
                assert posted.status_code == 202
                await asyncio.sleep(0)
                scheduler = app.state.timeout_scheduler
                store = scheduler._store
                assert [row.action_id for row in await store.list_pending()] == [ACTION_ID]
                approve_task = asyncio.create_task(
                    client.post(
                        "/slack/events",
                        content=_click("aisoc_action_approve"),
                        headers={"content-type": "application/x-www-form-urlencoded"},
                    )
                )
                assert await asyncio.to_thread(entered.wait, 5)
                await asyncio.sleep(0)
                assert [row.action_id for row in await store.list_pending()] == [ACTION_ID]
                deny = await client.post(
                    "/slack/events",
                    content=_click("aisoc_action_deny"),
                    headers={"content-type": "application/x-www-form-urlencoded"},
                )
                assert deny.status_code == 200
                for _ in range(5):
                    await asyncio.sleep(0)
                assert await store.list_pending() == []
                _Actions.approve_status = 500
                release.set()
                assert await asyncio.to_thread(approve_done.wait, 5)
                approve = await approve_task
                assert approve.status_code == 200
                for _ in range(5):
                    await asyncio.sleep(0)
                assert await store.list_pending() == []
                assert scheduler.pending == 0
    finally:
        release.set()


@pytest.mark.asyncio
@pytest.mark.usefixtures("actions_url")
async def test_an_absurd_timeout_is_refused_before_slack_is_called() -> None:
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://bot") as client:
            response = await client.post(
                "/internal/approval-card",
                json={**CARD, "timeout_seconds": 10**400},
                headers={"X-AiSOC-Internal-Token": TOKEN},
            )
    assert response.status_code == 422
    assert _slack_posts == []


@pytest.mark.asyncio
@pytest.mark.usefixtures("actions_url")
async def test_a_late_approve_does_not_join_an_in_flight_timeout_reject() -> None:
    entered = threading.Event()
    release = threading.Event()
    _Actions.reject_entered = entered
    _Actions.release_reject = release
    try:
        async with app.router.lifespan_context(app):
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://bot") as client:
                await _post_card(client)
                assert await asyncio.to_thread(entered.wait, 5)
                click = await client.post(
                    "/slack/events",
                    content=_click("aisoc_action_approve"),
                    headers={"content-type": "application/x-www-form-urlencoded"},
                )
                assert click.status_code == 200
                await asyncio.sleep(0.2)
                assert _paths() == [f"/api/v1/actions/{ACTION_ID}/reject"]
                release.set()
                await asyncio.sleep(0.2)
    finally:
        release.set()

    assert _paths() == [f"/api/v1/actions/{ACTION_ID}/reject"]
    assert _reject_bodies() == [b""]
