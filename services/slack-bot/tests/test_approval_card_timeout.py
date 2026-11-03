"""An undecided Slack approval times out after its card is posted."""

from __future__ import annotations

import asyncio
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from app.core.config import get_settings
from app.main import app
from httpx import ASGITransport, AsyncClient
from slack_sdk.web.async_client import AsyncWebClient
from slack_sdk.web.async_slack_response import AsyncSlackResponse

TOKEN = "internal-secret"
ACTION_ID = "act-timeout-1"

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

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler method name
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        type(self).received.append((self.path, body))
        payload = json.dumps({"id": ACTION_ID, "status": "rejected"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: object) -> None:
        return


@pytest.fixture
def actions_url(monkeypatch: pytest.MonkeyPatch) -> str:
    _Actions.received = []
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


def _deny_click() -> str:
    payload = {
        "type": "block_actions",
        "user": {"id": "U-SOC-LEAD"},
        "channel": {"id": "C-SOC"},
        "team": {"id": "T1"},
        "actions": [{"action_id": "aisoc_action_deny", "value": f"{ACTION_ID}|case-9", "type": "button"}],
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
                content=_deny_click(),
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
            assert click.status_code == 200
            await asyncio.sleep(1.5)

    bodies = _reject_bodies()
    assert len(bodies) == 1
    assert json.loads(bodies[0])["chatops_approver"]["platform_user_id"] == "U-SOC-LEAD"
