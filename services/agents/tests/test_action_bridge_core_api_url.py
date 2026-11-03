"""Regression: compose sets CORE_API_URL for agents; the bridge must read it.

``docker-compose.yml`` wires ``CORE_API_URL: http://api:8000`` on the agents
service while ``action_bridge`` previously looked only at ``API_SERVICE_URL``
and ``API_URL``. When those are unset the default still matched compose, so
misconfiguration only surfaced when operators pointed ``CORE_API_URL`` at a
different API host.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import httpx
import pytest
import respx

_AGENTS_ROOT = Path(__file__).resolve().parents[1]
if str(_AGENTS_ROOT) not in sys.path:
    sys.path.insert(0, str(_AGENTS_ROOT))


def _reload_bridge(monkeypatch: pytest.MonkeyPatch) -> object:
    monkeypatch.delenv("API_SERVICE_URL", raising=False)
    monkeypatch.delenv("API_URL", raising=False)
    module = importlib.import_module("app.playbook.action_bridge")
    return importlib.reload(module)


async def test_dispatch_uses_core_api_url_when_compose_name_is_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With only ``CORE_API_URL`` set, dispatch targets that origin."""
    monkeypatch.setenv("CORE_API_URL", "http://core-api.internal:9000")
    monkeypatch.setenv("AISOC_PLAYBOOK_ACTIONS_ENABLED", "1")
    monkeypatch.setenv("AISOC_AGENTS_SERVICE_TOKEN", "tok")
    bridge = _reload_bridge(monkeypatch)

    base = "http://core-api.internal:9000"
    async with respx.mock(base_url=base, assert_all_called=True) as router:
        router.post("/api/v1/playbook-steps/dispatch").mock(
            return_value=httpx.Response(200, json={"executed": True, "status": "executed"}),
        )
        await bridge.dispatch_step(capability="block_ip", tenant_id="t-1")
