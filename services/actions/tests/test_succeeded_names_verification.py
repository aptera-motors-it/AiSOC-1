from __future__ import annotations

import uuid

import pytest
from app.core.config import get_settings
from app.live_actions.executor import LiveActionExecutor
from app.live_actions.models import LiveActionRequest, LiveActionResult, LiveActionStatus
from app.live_actions.registry import register_executor, reset_for_tests
from app.main import app
from app.models.action import ActionType
from app.services.kill_switch import reset_cache as reset_kill_switch_cache
from app.services.tenant_policy import clear_cache as clear_policy_cache
from app.services.verification import VerificationOutcome
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


class _PreviewClaimsVerified(LiveActionExecutor):
    vendor_id = "repro"
    capability = "block_ip"

    async def execute(self, request: LiveActionRequest) -> LiveActionResult:
        return LiveActionResult(
            request_id=request.request_id,
            status=LiveActionStatus.SIMULATED,
            capability=request.capability,
            vendor_id=request.vendor_id,
            summary="preview only",
            verification=VerificationOutcome.VERIFIED,
        )


def test_dry_run_drops_executor_verification(monkeypatch) -> None:
    monkeypatch.setenv("AISOC_ACTIONS_SERVICE_TOKEN", _TOKEN)
    monkeypatch.setenv("AISOC_MATURITY_TIER", "L3")
    monkeypatch.setenv("AISOC_ACTIONS_DEFAULT_DRY_RUN", "0")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_DSN", raising=False)
    get_settings.cache_clear()
    reset_kill_switch_cache()
    clear_policy_cache()

    body = {
        "capability": "block_ip",
        "vendor_id": "repro",
        "target": "203.0.113.10",
        "dry_run": True,
    }
    with TestClient(app, headers={"Authorization": f"Bearer {_TOKEN}"}) as client:
        reset_for_tests()
        register_executor(_PreviewClaimsVerified())
        response = client.post("/api/v1/live-actions/dispatch", json=body)

    assert response.status_code == 200, response.text
    result = response.json()["result"]
    assert result["status"] == "simulated", result
    assert result["summary"] == "preview only", result
    assert result["verification"] is None, result
    reset_for_tests()
    get_settings.cache_clear()


@pytest.mark.parametrize(
    ("capability", "legacy", "status", "dry_run"),
    [
        ("block_ip", ActionType.BLOCK_IP, LiveActionStatus.SUCCEEDED, True),
        ("block_address", ActionType.BLOCK_IP, LiveActionStatus.SIMULATED, False),
        ("quarantine_path", ActionType.QUARANTINE_FILE, LiveActionStatus.SUCCEEDED, False),
    ],
)
def test_skipped_readback_strips_nested_verification(monkeypatch, capability, legacy, status, dry_run) -> None:
    monkeypatch.setenv("AISOC_ACTIONS_SERVICE_TOKEN", _TOKEN)
    monkeypatch.setenv("AISOC_MATURITY_TIER", "L3")
    monkeypatch.setenv("AISOC_ACTIONS_DEFAULT_DRY_RUN", "0")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DATABASE_DSN", raising=False)
    get_settings.cache_clear()
    reset_kill_switch_cache()
    clear_policy_cache()

    class _Claims(LiveActionExecutor):
        vendor_id = "repro"
        _legacy_action_type = legacy

        async def execute(self, request: LiveActionRequest) -> LiveActionResult:
            return LiveActionResult(
                request_id=request.request_id,
                status=status,
                capability=request.capability,
                vendor_id=request.vendor_id,
                summary="effect verified",
                verification=VerificationOutcome.VERIFIED,
                details={"verification": "verified", "verification_reason": "executor said so", "kept": True},
            )

    _Claims.capability = capability
    body = {
        "capability": capability,
        "vendor_id": "repro",
        "target": "203.0.113.10",
        "dry_run": dry_run,
        "confidence": 0.99,
        "tenant_id": str(uuid.uuid4()),
        "requested_by": "analyst@example.com",
    }
    with TestClient(app, headers={"Authorization": f"Bearer {_TOKEN}"}) as client:
        reset_for_tests()
        register_executor(_Claims())
        response = client.post("/api/v1/live-actions/dispatch", json=body)

    assert response.status_code == 200, response.text
    result = response.json()["result"]
    assert result["verification"] is None, result
    assert "verification" not in result["details"], result
    assert "verification_reason" not in result["details"], result
    assert result["details"]["kept"] is True, result
    assert result["summary"] == "preview only", result
    reset_for_tests()
    get_settings.cache_clear()
