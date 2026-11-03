from __future__ import annotations

import uuid

from app.core.config import get_settings
from app.live_actions.executor import LiveActionExecutor
from app.live_actions.models import LiveActionRequest, LiveActionResult, LiveActionStatus
from app.live_actions.registry import register_executor, reset_for_tests
from app.main import app
from app.models.action import ActionType
from app.services.kill_switch import reset_cache as reset_kill_switch_cache
from app.services.tenant_policy import clear_cache as clear_policy_cache
from fastapi.testclient import TestClient

_TOKEN = "test-actions-service-token"


class _VendorAccepted(LiveActionExecutor):
    vendor_id = "aws"
    capability = "block_address"
    _legacy_action_type = ActionType.BLOCK_IP

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return LiveActionResult(
            request_id=request.request_id,
            status=LiveActionStatus.SUCCEEDED,
            capability=request.capability,
            vendor_id=request.vendor_id,
            summary=f"blocked {request.target}",
        )


def test_succeeded_response_carries_verification_unverified(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_ACTIONS_SERVICE_TOKEN", _TOKEN)
    monkeypatch.setenv("AISOC_MATURITY_TIER", "L3")
    monkeypatch.setenv("AISOC_ACTIONS_DEFAULT_DRY_RUN", "0")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_DSN", raising=False)
    get_settings.cache_clear()
    reset_kill_switch_cache()
    clear_policy_cache()

    body = {
        "capability": "block_address",
        "vendor_id": "aws",
        "target": "203.0.113.10",
        "dry_run": False,
        "confidence": 0.99,
        "tenant_id": str(uuid.uuid4()),
        "requested_by": "analyst@example.com",
    }
    with TestClient(app, headers={"Authorization": f"Bearer {_TOKEN}"}) as client:
        reset_for_tests()
        register_executor(_VendorAccepted())
        response = client.post("/api/v1/live-actions/dispatch", json=body)

    assert response.status_code == 200, response.text
    result = response.json()["result"]
    assert result["status"] == "succeeded", result
    assert result["details"]["verification"] == "unverified", result
    assert result["verification"] == "unverified", result
    assert "verification=unverified" in result["summary"], result
    reset_for_tests()
    get_settings.cache_clear()
