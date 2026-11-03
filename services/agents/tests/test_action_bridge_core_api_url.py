from __future__ import annotations

import importlib
import sys
from pathlib import Path

import httpx
import pytest
import respx
from app.playbook import action_bridge

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))


def _reload_bridge() -> None:
    importlib.reload(action_bridge)


async def test_dispatch_uses_core_api_url_when_compose_name_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("API_SERVICE_URL", raising=False)
    monkeypatch.delenv("API_URL", raising=False)
    monkeypatch.setenv("CORE_API_URL", "http://core-api.internal:9000")
    monkeypatch.setenv("AISOC_PLAYBOOK_ACTIONS_ENABLED", "1")
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "tok")
    _reload_bridge()

    base = "http://core-api.internal:9000"
    async with respx.mock(base_url=base, assert_all_called=True) as router:
        router.post("/api/v1/playbook-steps/dispatch").mock(
            return_value=httpx.Response(200, json={"executed": True, "status": "executed"}),
        )
        await action_bridge.dispatch_step(capability="block_ip", tenant_id="t-1")


async def test_dispatch_still_uses_api_service_url_without_core(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("CORE_API_URL", raising=False)
    monkeypatch.delenv("API_URL", raising=False)
    monkeypatch.setenv("API_SERVICE_URL", "http://legacy-svc:8001")
    monkeypatch.setenv("AISOC_PLAYBOOK_ACTIONS_ENABLED", "1")
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "tok")
    _reload_bridge()

    base = "http://legacy-svc:8001"
    async with respx.mock(base_url=base, assert_all_called=True) as router:
        router.post("/api/v1/playbook-steps/dispatch").mock(
            return_value=httpx.Response(200, json={"executed": True, "status": "executed"}),
        )
        await action_bridge.dispatch_step(capability="block_ip", tenant_id="t-1")


async def test_empty_core_api_url_falls_back_to_api_service_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CORE_API_URL", "")
    monkeypatch.delenv("API_URL", raising=False)
    monkeypatch.setenv("API_SERVICE_URL", "http://legacy-svc:8001")
    monkeypatch.setenv("AISOC_PLAYBOOK_ACTIONS_ENABLED", "1")
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "tok")
    _reload_bridge()

    base = "http://legacy-svc:8001"
    async with respx.mock(base_url=base, assert_all_called=True) as router:
        router.post("/api/v1/playbook-steps/dispatch").mock(
            return_value=httpx.Response(200, json={"executed": True, "status": "executed"}),
        )
        await action_bridge.dispatch_step(capability="block_ip", tenant_id="t-1")
