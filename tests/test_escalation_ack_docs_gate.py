"""The escalation ack-clock docs gate must catch the drift that shipped.

F60: README and ``bridge.py`` said console acknowledge stops Teams paging, but
only the war-room channel acknowledge decision writes ``aisoc_cases.acknowledged_at``.
A gate that only passes on the real tree after the fix is indistinguishable from
no gate — these tests pin the comparison on scratch trees too.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "check_escalation_ack_docs.py"


def _import_gate():
    spec = importlib.util.spec_from_file_location("_escalation_ack_docs_gate", GATE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_stale_console_ack_claim_is_refused(tmp_path: Path) -> None:
    """The gate must refuse operator docs that resurrect the console-ack myth."""
    module = _import_gate()
    root = tmp_path
    stale_readme = module.GOOD_README.replace(
        "war-room **acknowledge**",
        "console's acknowledge action and joining the case's war room",
    )
    module._write_minimal_tree(
        root,
        readme=stale_readme,
        bridge_doc=module.GOOD_BRIDGE_DOC,
        war_room='if decision == "acknowledge":\n    "UPDATE aisoc_cases SET acknowledged_at = COALESCE(acknowledged_at, :now)"\n',
    )
    findings = module.gate_escalation_ack_docs(root)
    assert findings
    joined = " ".join(f.render() for f in findings)
    assert "console" in joined.lower() or "joining" in joined.lower()


def test_the_live_tree_matches_the_ack_clock_writer() -> None:
    """After the fix, production docs and code must agree."""
    module = _import_gate()
    assert module.gate_escalation_ack_docs(REPO_ROOT) == []


def test_self_test_proves_the_gate_is_not_vacuous() -> None:
    result = subprocess.run(
        [sys.executable, str(GATE), "--self-test"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_extra_ack_clock_writer_claim_is_refused(tmp_path: Path) -> None:
    module = _import_gate()
    module._write_minimal_tree(
        tmp_path,
        readme=module.GOOD_README + "\nThe web UI PATCH is also an ack-clock writer.\n",
        bridge_doc=module.GOOD_BRIDGE_DOC,
        war_room='if decision == "acknowledge":\n    "UPDATE aisoc_cases SET acknowledged_at = COALESCE(acknowledged_at, :now)"\n',
    )
    assert module.gate_escalation_ack_docs(tmp_path)


def test_only_war_room_writes_the_case_ack_column() -> None:
    module = _import_gate()
    writers: list[str] = []
    for path in (REPO_ROOT / "services").rglob("*.py"):
        rel = path.relative_to(REPO_ROOT).as_posix()
        if "/migrations/" in rel:
            continue
        body = path.read_text(encoding="utf-8")
        if module._mentions_case_ack_write(body):
            writers.append(rel)
    assert writers == ["services/api/app/services/war_room.py"]
