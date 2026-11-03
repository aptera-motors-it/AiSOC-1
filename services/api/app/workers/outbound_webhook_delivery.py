"""Drain the outbound-webhook retry queue.

Without this the queue is a table that fills up: ``enqueue_event`` writes a
pending row and nothing ever attempts it, which is the "mechanism exists,
nothing calls it" shape that this plan keeps finding. The dead-letter view
would read empty forever, which is the most reassuring possible way to be
wrong about whether a tenant's SIEM has their alerts.
"""

from __future__ import annotations

import asyncio
import os
import uuid

import structlog
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import AsyncSessionLocal
from app.services.outbound_webhooks import attempt_delivery, due_deliveries

logger = structlog.get_logger(__name__)

__all__ = ["run_forever", "run_once"]

#: Tight enough that the 30-second first retry means roughly 30 seconds.
POLL_INTERVAL_SECONDS = float(os.getenv("OUTBOUND_WEBHOOK_POLL_INTERVAL_SECONDS", "15"))

#: Per tick. Bounds how long one pass can hold the loop when a receiver is
#: timing out: 25 deliveries at a 10-second timeout is the worst case.
BATCH_SIZE = int(os.getenv("OUTBOUND_WEBHOOK_BATCH_SIZE", "25"))


async def _bind_tenant(db: AsyncSession, tenant_id: uuid.UUID) -> None:
    await db.execute(
        text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
        {"tenant_id": str(tenant_id)},
    )


async def run_once() -> dict[str, int]:
    """Attempt every delivery that has come due. Returns a small tally."""
    attempted = delivered = dead = 0
    for _ in range(BATCH_SIZE):
        async with AsyncSessionLocal() as db:
            claimed = await due_deliveries(db, limit=1)
            if not claimed:
                break
            delivery, webhook = claimed[0]
            await _bind_tenant(db, delivery.tenant_id)
            await attempt_delivery(delivery, webhook)
            attempted += 1
            delivered += delivery.status == "delivered"
            dead += delivery.status == "dead"
            await db.commit()
    if attempted:
        logger.info("outbound_webhook.swept", attempted=attempted, delivered=delivered, dead=dead)
    return {"attempted": attempted, "delivered": delivered, "dead": dead}


async def run_forever() -> None:
    """Poll until cancelled. A failed pass must not end the loop."""
    while True:
        try:
            await run_once()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.warning("outbound_webhook.sweep_failed", error=str(exc)[:300])
        await asyncio.sleep(POLL_INTERVAL_SECONDS)
