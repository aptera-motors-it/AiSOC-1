"""Phase B3 — durable approval-SLA timer store tests.

Proves the scheduler persists pending timers, drops them on human decision /
fire, and recovers (re-arms) them after a simulated restart — the fix for
"a bot restart forgets a pending auto-reject forever".
"""

from __future__ import annotations

import asyncio
import time

import pytest
from app.services.approval_timeout import ApprovalTimeoutScheduler
from app.services.timer_store import InMemoryTimerStore, TimerRecord

pytestmark = pytest.mark.asyncio


async def _noop(_action_id: str) -> dict:
    return {"ok": True}


def _scheduler(store: InMemoryTimerStore) -> ApprovalTimeoutScheduler:
    return ApprovalTimeoutScheduler(approve_fn=_noop, reject_fn=_noop, store=store)


async def test_schedule_persists_a_timer_row():
    store = InMemoryTimerStore()
    sched = _scheduler(store)
    sched.schedule("act-1", timeout_seconds=60, safe_default="rejected", case_id="c1")
    await asyncio.sleep(0)  # let the fire-and-forget put() run
    rows = await store.list_pending()
    assert [r.action_id for r in rows] == ["act-1"]
    assert rows[0].safe_default == "rejected"
    await sched.aclose()


async def test_cancel_removes_durable_row():
    store = InMemoryTimerStore()
    sched = _scheduler(store)
    sched.schedule("act-2", timeout_seconds=60)
    await asyncio.sleep(0)
    sched.cancel("act-2")
    await asyncio.sleep(0)
    assert await store.list_pending() == []
    await sched.aclose()


async def test_fire_removes_durable_row():
    store = InMemoryTimerStore()
    sched = _scheduler(store)
    task = sched.schedule("act-3", timeout_seconds=0.01, safe_default="rejected")
    _ = await task  # wait for the timer to fire
    assert await store.list_pending() == []


async def test_recover_rearms_pending_timers_after_restart():
    # Simulate a store that survived a restart with one pending row.
    store = InMemoryTimerStore()
    await store.put(TimerRecord(action_id="act-4", fire_at_epoch=time.time() + 60, safe_default="rejected", case_id="c9"))

    fresh = _scheduler(store)  # brand-new scheduler (empty in-memory timers)
    assert fresh.pending == 0
    recovered = await fresh.recover()
    assert recovered == 1
    assert fresh.pending == 1
    await fresh.aclose()


async def test_recover_fires_overdue_timer_promptly():
    store = InMemoryTimerStore()
    fired: list[str] = []

    async def _reject(action_id: str) -> dict:
        fired.append(action_id)
        return {"ok": True}

    # Deadline already in the past → should fire ~immediately on recover.
    await store.put(TimerRecord(action_id="act-5", fire_at_epoch=time.time() - 5, safe_default="rejected"))
    sched = ApprovalTimeoutScheduler(approve_fn=_noop, reject_fn=_reject, store=store)
    await sched.recover()
    # Give the near-zero timer a couple of loop ticks to fire.
    for _ in range(5):
        await asyncio.sleep(0)
        if fired:
            break
    assert fired == ["act-5"]


class _DeleteWaits(InMemoryTimerStore):
    """A delete that pauses, the way a Postgres delete waits on the pool."""

    def __init__(self) -> None:
        super().__init__()
        self.started = asyncio.Event()
        self.release = asyncio.Event()

    async def delete(self, action_id: str) -> None:
        self.started.set()
        await self.release.wait()
        await super().delete(action_id)


async def test_a_stale_resume_does_not_rearm_after_a_later_suspend():
    store = InMemoryTimerStore()
    fired: list[str] = []

    async def _reject(action_id: str) -> dict:
        fired.append(action_id)
        return {"ok": True}

    sched = ApprovalTimeoutScheduler(approve_fn=_noop, reject_fn=_reject, store=store)
    sched.schedule("act-stale", timeout_seconds=0.05, safe_default="rejected", case_id="c")
    await asyncio.sleep(0)
    try:
        first = sched.suspend("act-stale")
        assert first is not None
        await asyncio.sleep(0.08)
        sched.schedule("act-stale", timeout_seconds=60, safe_default="rejected", case_id="c")
        await asyncio.sleep(0)
        second = sched.suspend("act-stale")
        assert second is not None
        assert sched.pending == 0
        sched.resume(first)
        await asyncio.sleep(0.05)
        assert fired == []
        assert sched.pending == 0
        assert [row.action_id for row in await store.list_pending()] == ["act-stale"]
    finally:
        await sched.aclose()


async def test_a_delete_started_by_suspend_does_not_drop_the_resumed_row():
    store = _DeleteWaits()
    sched = _scheduler(store)
    sched.schedule("act-9", timeout_seconds=60, safe_default="rejected", case_id="c9")
    await asyncio.sleep(0)
    try:
        record = sched.suspend("act-9")
        assert record is not None
        await asyncio.sleep(0)
        sched.resume(record)
        await asyncio.sleep(0)
        if store.started.is_set():
            store.release.set()
            await asyncio.sleep(0)
        assert [row.action_id for row in await store.list_pending()] == ["act-9"]
    finally:
        store.release.set()
        await sched.aclose()


async def test_default_store_is_in_memory_non_durable():
    sched = ApprovalTimeoutScheduler(approve_fn=_noop, reject_fn=_noop)
    sched.schedule("act-6", timeout_seconds=60)
    await asyncio.sleep(0)
    # No store injected → a fresh scheduler recovers nothing (non-durable).
    fresh = ApprovalTimeoutScheduler(approve_fn=_noop, reject_fn=_noop)
    assert await fresh.recover() == 0
    await sched.aclose()
