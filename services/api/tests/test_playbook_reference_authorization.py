"""Transport-level authorization for decrypted playbook references."""

from __future__ import annotations

import uuid
from typing import Any

from app.api.v1.deps import CurrentUser
from app.api.v1.endpoints import playbook_steps
from app.services import playbook_references
from fastapi import FastAPI
from fastapi.testclient import TestClient


def test_an_analyst_cannot_read_decrypted_playbook_references(monkeypatch: Any) -> None:
    """A console session must not receive integration credentials."""
    tenant_id = uuid.uuid4()
    analyst = CurrentUser(
        user_id=uuid.uuid4(),
        tenant_id=tenant_id,
        role="soc_analyst",
        email="analyst@example.invalid",
    )

    async def resolve_secret(*args: Any, **kwargs: Any) -> dict[str, dict[str, Any]]:
        return {
            "IDP_BEARER_HEADERS": {
                "kind": "headers",
                "headers": {"Authorization": "Bearer secret-value"},
                "secret": True,
            }
        }

    monkeypatch.setattr(playbook_references, "resolve", resolve_secret)
    app = FastAPI()
    app.include_router(playbook_steps.router, prefix="/api/v1")
    app.dependency_overrides[playbook_steps.optional_user] = lambda: analyst
    app.dependency_overrides[playbook_steps.get_db] = lambda: None

    response = TestClient(app).post(
        "/api/v1/playbook-steps/references",
        json={"names": ["IDP_BEARER_HEADERS"]},
    )

    assert response.status_code == 403
    assert "secret-value" not in response.text


def test_the_agents_service_can_read_decrypted_playbook_references(monkeypatch: Any) -> None:
    """The internal worker still receives the values needed for one step."""
    tenant_id = uuid.uuid4()
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "service-token")

    async def resolve_secret(*args: Any, **kwargs: Any) -> dict[str, dict[str, Any]]:
        return {"IDP_BEARER_HEADERS": {"kind": "headers", "headers": {"Authorization": "Bearer secret-value"}}}

    monkeypatch.setattr(playbook_references, "resolve", resolve_secret)
    app = FastAPI()
    app.include_router(playbook_steps.router, prefix="/api/v1")
    app.dependency_overrides[playbook_steps.optional_user] = lambda: None
    app.dependency_overrides[playbook_steps.get_db] = lambda: None

    response = TestClient(app).post(
        "/api/v1/playbook-steps/references",
        headers={"X-Aisoc-Service-Token": "service-token"},
        json={"tenant_id": str(tenant_id), "names": ["IDP_BEARER_HEADERS"]},
    )

    assert response.status_code == 200
    assert response.json()["references"]["IDP_BEARER_HEADERS"]["headers"]["Authorization"] == "Bearer secret-value"
