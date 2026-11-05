"""Retry honeytoken trips whose alert was not accepted.

``webhook_trigger`` sends once. A receiver that is down, or a publish that
fails, leaves ``alert_sent`` false and used to stop there, so the trip was
visible only in this service's own table. This loop sends those rows again
until one is accepted. The wait grows while a pass still has undelivered
rows, and returns to the base interval once a pass is clean.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.config import settings
from app.models.honeytoken import Honeytoken, HoneytokenTrigger
from app.services.alerting import send_alert

LOG = logging.getLogger(__name__)

_BATCH = 25
_MAX_DELAY_SECONDS = 30.0


async def deliver_unsent(session_factory: async_sessionmaker[AsyncSession]) -> tuple[int, int]:
    """Send one batch of trips that are not marked delivered.

    Returns ``(delivered, still_pending)`` for the rows this pass looked at.
    """
    async with session_factory() as session:
        result = await session.execute(
            select(HoneytokenTrigger, Honeytoken)
            .join(Honeytoken, Honeytoken.id == HoneytokenTrigger.honeytoken_id)
            .where(HoneytokenTrigger.alert_sent.is_(False))
            .order_by(HoneytokenTrigger.triggered_at)
            .limit(_BATCH)
        )
        pending = [
            (
                trigger.id,
                trigger.honeytoken_id,
                trigger.tenant_id,
                token.token_type,
                token.name,
                trigger.source_ip,
                trigger.triggered_at,
            )
            for trigger, token in result.all()
        ]

    delivered = 0
    still_pending = 0
    for trigger_id, honeytoken_id, tenant_id, token_type, token_name, source_ip, triggered_at in pending:
        ok = await send_alert(
            honeytoken_id=honeytoken_id,
            tenant_id=tenant_id,
            token_type=token_type,
            token_name=token_name,
            trigger_id=trigger_id,
            source_ip=source_ip,
            triggered_at=triggered_at,
        )
        if not ok:
            still_pending += 1
            continue
        async with session_factory() as session:
            await session.execute(
                update(HoneytokenTrigger)
                .where(
                    HoneytokenTrigger.id == trigger_id,
                    HoneytokenTrigger.alert_sent.is_(False),
                )
                .values(alert_sent=True, alert_sent_at=datetime.now(UTC))
            )
            await session.commit()
        delivered += 1
    return delivered, still_pending


async def run_alert_retry(session_factory: async_sessionmaker[AsyncSession], stop: asyncio.Event) -> None:
    """Run :func:`deliver_unsent` until ``stop`` is set."""
    base = max(0.2, float(settings.alert_retry_seconds))
    delay = base
    while not stop.is_set():
        delivered = 0
        pending = 0
        try:
            delivered, pending = await deliver_unsent(session_factory)
        except Exception:
            LOG.exception("honeytoken alert retry failed")
            pending = 1
        if pending and delivered == 0:
            delay = min(delay * 2, _MAX_DELAY_SECONDS)
        else:
            delay = base
        try:
            await asyncio.wait_for(stop.wait(), timeout=delay)
        except TimeoutError:
            continue
