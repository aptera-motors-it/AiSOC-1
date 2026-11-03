from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import psycopg
import pytest
from app import bridge

DSN = os.environ.get("AISOC_TEST_POSTGRES", "").strip()
pytestmark = pytest.mark.skipif(not DSN, reason="set AISOC_TEST_POSTGRES=postgresql://... to run the live escalation proof")


class Receiver:
    def __init__(self) -> None:
        self.posts: list[dict] = []
        self.reject: set[str] = set()
        self.state_path: Path | None = None
        self.saved_ids_at_post: list[list[str]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length))
                saved: list[str] = []
                if outer.state_path is not None and outer.state_path.exists():
                    saved = sorted(json.loads(outer.state_path.read_text(encoding="utf-8"))["escalations"])
                outer.saved_ids_at_post.append(saved)
                refused = any(marker in (body.get("title") or "") for marker in outer.reject)
                status = 500 if refused else 200
                outer.posts.append({**body, "_status": status})
                self.send_response(status)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}/hook"
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def delivered_for(self, ref: str) -> int:
        return sum(1 for post in self.posts if post.get("case_id") == ref and post["_status"] == 200)

    def digests(self) -> list[dict]:
        return [post for post in self.posts if post.get("severity") == "DIGEST"]

    def close(self) -> None:
        self._server.shutdown()
        self._thread.join(timeout=5)


@pytest.fixture
def receiver():
    server = Receiver()
    yield server
    server.close()


@pytest.fixture
def cases():
    tenant = uuid.uuid4()
    tag = uuid.uuid4().hex[:8]
    refused_id = uuid.uuid4()
    other_id = uuid.uuid4()
    high_id = uuid.uuid4()
    refused_ref = f"R-{tag}"
    other_ref = f"O-{tag}"
    rows = (
        (refused_id, f"REFUSE-{tag} oldest", "critical", datetime(1970, 1, 1, tzinfo=UTC), refused_ref),
        (other_id, f"second critical {tag}", "critical", datetime(1970, 1, 2, tzinfo=UTC), other_ref),
        (high_id, f"high {tag}", "high", datetime(1970, 1, 3, tzinfo=UTC), f"H-{tag}"),
    )
    with psycopg.connect(DSN) as conn:
        conn.execute(
            "INSERT INTO tenants (id, name, slug) VALUES (%s, %s, %s)",
            (tenant, f"p20-{tag}", f"p20-{tag}"),
        )
        for case_id, title, severity, opened, ref in rows:
            conn.execute(
                "INSERT INTO aisoc_cases (id, tenant_id, title, severity, status, opened_at, case_number) "
                "VALUES (%s, %s, %s, %s, 'new', %s, %s)",
                (case_id, tenant, title, severity, opened, ref),
            )
    yield {
        "marker": f"REFUSE-{tag}",
        "refused_id": str(refused_id),
        "other_id": str(other_id),
        "refused_ref": refused_ref,
        "other_ref": other_ref,
    }
    with psycopg.connect(DSN) as conn:
        conn.execute("DELETE FROM aisoc_cases WHERE tenant_id = %s", (tenant,))
        conn.execute("DELETE FROM tenants WHERE id = %s", (tenant,))


def _run_tick(state: dict) -> str | None:
    try:
        bridge.tick(state)
    except Exception as exc:
        return type(exc).__name__
    return None


def test_refused_page_does_not_stop_the_others_or_double_send_on_restart(monkeypatch, tmp_path, receiver, cases):
    monkeypatch.setattr(bridge, "DATABASE_URL", DSN)
    monkeypatch.setattr(bridge, "TEAMS_URL", receiver.url)
    monkeypatch.setattr(bridge, "STATE_FILE", str(tmp_path / "escalation-state.json"))
    monkeypatch.setattr(bridge, "ACK_GRACE_MINUTES", 0)
    monkeypatch.setattr(bridge, "DIGEST_HOUR_UTC", 0)
    receiver.reject.add(cases["marker"])

    error = _run_tick(bridge.load_state())
    assert receiver.delivered_for(cases["other_ref"]) == 1, error
    assert len(receiver.digests()) == 1, error
    assert error is None
    saved = json.loads((tmp_path / "escalation-state.json").read_text(encoding="utf-8"))
    assert cases["other_id"] in saved["escalations"]
    assert cases["refused_id"] not in saved["escalations"]
    assert saved["digest_last"] == datetime.now(UTC).strftime("%Y-%m-%d")

    error = _run_tick(bridge.load_state())
    assert error is None
    assert receiver.delivered_for(cases["other_ref"]) == 1
    assert receiver.delivered_for(cases["refused_ref"]) == 0
    assert len(receiver.digests()) == 1


def test_second_page_sees_the_first_case_already_saved(monkeypatch, tmp_path, receiver, cases):
    state_file = tmp_path / "escalation-state.json"
    receiver.state_path = state_file
    monkeypatch.setattr(bridge, "DATABASE_URL", DSN)
    monkeypatch.setattr(bridge, "TEAMS_URL", receiver.url)
    monkeypatch.setattr(bridge, "STATE_FILE", str(state_file))
    monkeypatch.setattr(bridge, "ACK_GRACE_MINUTES", 0)
    monkeypatch.setattr(bridge, "DIGEST_HOUR_UTC", 24)

    error = _run_tick(bridge.load_state())
    assert error is None
    assert [post["case_id"] for post in receiver.posts] == [cases["refused_ref"], cases["other_ref"]]
    assert receiver.saved_ids_at_post[0] == []
    assert receiver.saved_ids_at_post[1] == [cases["refused_id"]]


def test_failed_state_write_still_pages_every_open_case(monkeypatch, receiver, cases):
    monkeypatch.setattr(bridge, "DATABASE_URL", DSN)
    monkeypatch.setattr(bridge, "TEAMS_URL", receiver.url)
    monkeypatch.setattr(bridge, "STATE_FILE", "escalation-state.json")
    monkeypatch.setattr(bridge, "ACK_GRACE_MINUTES", 0)
    monkeypatch.setattr(bridge, "DIGEST_HOUR_UTC", 0)

    error = _run_tick(bridge.load_state())
    assert receiver.delivered_for(cases["refused_ref"]) == 1, error
    assert receiver.delivered_for(cases["other_ref"]) == 1, error
    assert len(receiver.digests()) == 1, error
