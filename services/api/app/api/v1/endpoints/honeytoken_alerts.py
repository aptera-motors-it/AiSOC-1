"""Receive a honeytoken trip and publish it as a finding.

Fusion promotes OCSF findings from ``aisoc.raw_events`` into the alert
table. A trip that never reaches that topic never becomes an alert. This
route is the receiver the honeytoken service posts to. It accepts only a
service token, checks the HMAC over the raw body with that same token, and
publishes one normalized event. A publish failure is a 503 so the caller
leaves the trip unsent and tries again.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import uuid
from typing import Annotated, Any

from aiokafka import AIOKafkaProducer
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.deps import resolve_service_token
from app.core.kafka_security import kafka_client_kwargs
from app.db.database import get_db
from app.models.tenant import Tenant
from app.security.tenant_scope import scoped_tenant_or_403

LOG = logging.getLogger(__name__)

router = APIRouter(prefix="/internal/honeytoken-alerts", tags=["honeytoken-alerts"])

_TOPIC_ENV = "KAFKA_TOPIC_RAW_EVENTS"
_DEFAULT_TOPIC = "aisoc.raw_events"


class HoneytokenTrip(BaseModel):
    event: str
    honeytoken_id: uuid.UUID
    tenant_id: uuid.UUID
    token_type: str
    token_name: str
    trigger_id: uuid.UUID
    source_ip: str | None = None
    triggered_at: str


class _IngestPrincipal:
    """The tenant the service token declared, checked against the table."""

    def __init__(self, tenant_id: uuid.UUID) -> None:
        self.tenant_id = tenant_id


def _presented_token(authorization: str | None) -> str | None:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization[len("Bearer ") :].strip()
    return token or None


def _signatures_match(presented: str | None, secret: str, body: bytes) -> bool:
    if not presented or not secret or not presented.startswith("sha256="):
        return False
    digest = presented[len("sha256=") :]
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    if len(digest) != len(expected):
        return False
    return hmac.compare_digest(digest, expected)


async def require_service_auth(
    db: Annotated[AsyncSession, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
    x_aisoc_tenant_id: Annotated[str | None, Header()] = None,
) -> _IngestPrincipal:
    """Fail closed unless the bearer token matches and names a real tenant."""
    expected = resolve_service_token()
    presented = _presented_token(authorization)
    if not expected or not presented or len(presented) != len(expected) or not hmac.compare_digest(presented, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing service token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not x_aisoc_tenant_id or not x_aisoc_tenant_id.strip():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="service token must declare the tenant it acts for on X-AiSOC-Tenant-ID",
        )
    try:
        tenant_id = uuid.UUID(x_aisoc_tenant_id.strip())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="X-AiSOC-Tenant-ID must be a UUID",
        ) from None
    found = await db.execute(select(Tenant.id).where(Tenant.id == tenant_id))
    if found.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="service token named a tenant that does not exist",
        )
    return _IngestPrincipal(tenant_id)


def _event(body: HoneytokenTrip, tenant_id: uuid.UUID) -> dict[str, Any]:
    """One ingest-shaped event. Findings are what fusion promotes."""
    name = body.token_name.replace("\r", " ").replace("\n", " ")[:200]
    ocsf: dict[str, Any] = {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "category_uid": 2,
        "category_name": "Findings",
        "severity_id": 5,
        "severity": "Critical",
        "message": f"Honeytoken tripped: {name}",
        "time": body.triggered_at,
        "tenant_uid": str(tenant_id),
        "metadata": {
            "uid": str(body.trigger_id),
            "product": {"name": "Honeytokens", "vendor_name": "AiSOC"},
        },
        "finding": {
            "uid": str(body.trigger_id),
            "desc": f"Honeytoken {name} ({body.token_type}) was used.",
        },
    }
    if body.source_ip:
        ocsf["src_endpoint"] = {"ip": body.source_ip}
    return {
        "id": str(body.trigger_id),
        "connector_id": "honeytokens",
        "connector_type": "honeytoken",
        "tenant_id": str(tenant_id),
        "normalization_version": "1",
        "ocsf_event": ocsf,
    }


async def _publish(event: dict[str, Any]) -> None:
    brokers = (os.getenv("KAFKA_BOOTSTRAP_SERVERS") or "").strip()
    if not brokers:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="alert was not published",
        )
    topic = (os.getenv(_TOPIC_ENV) or _DEFAULT_TOPIC).strip()
    producer = AIOKafkaProducer(
        bootstrap_servers=brokers,
        **kafka_client_kwargs(),
    )
    try:
        await producer.start()
        await producer.send_and_wait(
            topic,
            json.dumps(event).encode(),
            key=f"{event['tenant_id']}:{event['id']}".encode(),
        )
    except Exception as exc:
        LOG.error("honeytoken alert publish failed: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="alert was not published",
        ) from None
    finally:
        try:
            await producer.stop()
        except Exception as exc:
            LOG.error("honeytoken alert producer stop failed: %s", exc)


@router.post("", status_code=204, response_model=None)
async def ingest_honeytoken_trip(
    body: HoneytokenTrip,
    request: Request,
    principal: Annotated[_IngestPrincipal, Depends(require_service_auth)],
) -> None:
    """Publish one trip. The tenant is the principal's, not the body's alone."""
    tenant_id = scoped_tenant_or_403(principal, body.tenant_id)
    if body.event != "honeytoken.triggered":
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="unsupported event")
    secret = resolve_service_token()
    raw = await request.body()
    presented = request.headers.get("x-aisoc-signature")
    if not _signatures_match(presented, secret, raw):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid signature")
    await _publish(_event(body, tenant_id))
