"""Inbound Teams callbacks must cross the Bot Framework authentication boundary."""

from __future__ import annotations

from app.main import app
from app.services.aisoc_clients import build_audit_sink
from fastapi.testclient import TestClient


def test_teams_callback_without_proxy_authentication_is_refused(monkeypatch) -> None:
    monkeypatch.delenv("AISOC_TEAMS_PROXY_AUTH_SECRET", raising=False)

    with TestClient(app) as client:
        response = client.post("/teams/messages", json={"value": {"action": {"data": {}}}})

    assert response.status_code == 503


def test_teams_callback_with_an_invalid_proxy_secret_is_refused(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_TEAMS_PROXY_AUTH_SECRET", "expected")

    with TestClient(app) as client:
        response = client.post(
            "/teams/messages",
            json={"value": {"action": {"data": {}}}},
            headers={"X-AiSOC-Teams-Proxy-Auth": "forged"},
        )

    assert response.status_code == 401


def test_built_teams_image_never_uses_a_null_audit_sink() -> None:
    assert type(build_audit_sink()).__name__ != "_NullAuditSink"
