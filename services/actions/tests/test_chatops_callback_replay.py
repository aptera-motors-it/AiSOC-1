"""The ChatOps callback route claims replies in durable storage before effects."""

from __future__ import annotations

from uuid import uuid4

import pytest
from app.api import router
from app.security.chatops_token import mint_token


@pytest.mark.asyncio
async def test_replayed_callback_is_stopped_by_the_durable_claim(monkeypatch) -> None:
    token = mint_token(
        action_id=uuid4(),
        case_id=uuid4(),
        tenant_id=uuid4(),
        choice="acknowledge",
        user_ref="analyst@example.invalid",
        secret="test-secret",
        ttl_seconds=900,
    )

    class _Settings:
        AISOC_CHATOPS_RESPONSE_SECRET = "test-secret"

    async def _already_claimed(action_id: str) -> bool:
        return False

    monkeypatch.setattr(router, "get_settings", lambda: _Settings())
    monkeypatch.setattr(router.action_store, "claim_chatops_reply", _already_claimed, raising=False)

    response = await router.chatops_callback(token)

    assert response.status_code == 200
    assert b"Response already recorded" in response.body
