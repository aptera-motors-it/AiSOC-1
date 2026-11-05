#!/usr/bin/env python3
"""Escalation paging docs must name the only writer of ``aisoc_cases.acknowledged_at``.

The ack-clock bridge stops paging when that column is set. Operator docs once
said the console acknowledge action (and joining a war room) stopped the clock,
but no console route writes the column: only the war-room channel
**acknowledge** decision in ``services/api/app/services/war_room.py`` does.
Operators who believe console work stops Teams nagging will leave CRITICAL
cases paging until someone clicks acknowledge in chat.

This gate keeps the two operator-facing documents aligned with the code path
and refuses a second runtime writer of the case ack clock.
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root  # noqa: E402

README = Path("services/escalations/README.md")
BRIDGE = Path("services/escalations/app/bridge.py")
WAR_ROOM = Path("services/api/app/services/war_room.py")

FORBIDDEN_DOC_PHRASES = (
    "that is the console",
    "the console's",
    "console acknowledge action",
    "joining the case's war room",
    "war-room join write",
    "also an ack-clock writer",
)

WAR_ROOM_ACK = re.compile(r"war-room\s+acknowledge", re.IGNORECASE)

EXCLUSIVE_WRITER = re.compile(
    r"today\s+only\s+(?:the\s+)?war-room\s+acknowledge[\s\S]{0,120}\bwrites\b",
    re.IGNORECASE,
)

EXCLUSIVE_README_WRITER = re.compile(
    r"today\s+only\s+the\s+war-room\s+acknowledge",
    re.IGNORECASE,
)

ALT_ACK_WRITER = re.compile(
    r"console|clicking\s+acknowledge|acknowledge\s+button|joining\s+(?:the\s+)?(?:case'?s\s+)?war[- ]room|,\s*or\s+[^.\n]{0,100}\bwrite",
    re.IGNORECASE,
)

MIGRATION_ACK_WRITE = re.compile(
    r"\bCREATE\s+TRIGGER\b|NEW\.acknowledged_at\s*:=|UPDATE\s+aisoc_cases\s+SET[^;]*acknowledged_at\s*=",
    re.IGNORECASE,
)

CASE_ACK_SET = re.compile(
    r"UPDATE\s+aisoc_cases\s+SET[^\n;]*acknowledged_at",
    re.IGNORECASE,
)


def _bridge_module_doc(root: Path) -> str:
    path = root / BRIDGE
    if not path.is_file():
        return ""
    text = path.read_text(encoding="utf-8")
    if text.startswith('"""'):
        parts = text.split('"""', 2)
        return parts[1] if len(parts) > 2 else ""
    if text.startswith("'''"):
        parts = text.split("'''", 2)
        return parts[1] if len(parts) > 2 else ""
    return ""


def _mentions_case_ack_write(body: str) -> bool:
    if CASE_ACK_SET.search(body):
        return True
    if re.search(
        r"UPDATE[^\n]{0,160}aisoc_cases[^\n]{0,120}SET[^\n]{0,120}acknowledged_at",
        body,
        re.IGNORECASE,
    ):
        return True
    return bool(re.search(r"\.values\s*\([^)]*acknowledged_at\s*=", body, re.IGNORECASE))


@dataclass(frozen=True)
class Finding:
    where: str
    detail: str

    def render(self) -> str:
        return f"{self.where}: {self.detail}"


def _read(root: Path, rel: Path) -> str:
    path = root / rel
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def _normalize_doc(text: str) -> str:
    return re.sub(r"\*+", "", text.lower())


def _gate_war_room_ack_path(source: str) -> list[Finding]:
    findings: list[Finding] = []
    if not source:
        return [Finding(str(WAR_ROOM), "missing; cannot verify the ack-clock writer")]

    if not re.search(r'CHANNEL_DECISIONS[^)]*"acknowledge"', source):
        findings.append(
            Finding(
                str(WAR_ROOM),
                'CHANNEL_DECISIONS must include "acknowledge" so the documented writer exists',
            )
        )

    ack_branch = re.search(
        r'if decision == "acknowledge":(.*?)elif decision == "escalate":',
        source,
        re.DOTALL,
    )
    if ack_branch is None:
        findings.append(
            Finding(
                str(WAR_ROOM),
                'acknowledged_at must be written only under `if decision == "acknowledge":`',
            )
        )
        return findings

    if not CASE_ACK_SET.search(ack_branch.group(1)):
        findings.append(
            Finding(
                str(WAR_ROOM),
                "the acknowledge branch must UPDATE aisoc_cases.acknowledged_at",
            )
        )

    without_ack = re.sub(
        r'if decision == "acknowledge":.*?elif decision == "escalate":',
        "",
        source,
        count=1,
        flags=re.DOTALL,
    )
    if CASE_ACK_SET.search(without_ack):
        findings.append(
            Finding(
                str(WAR_ROOM),
                "aisoc_cases.acknowledged_at must not be written outside the acknowledge branch",
            )
        )
    return findings


def _migration_case_ack_writers(root: Path) -> list[str]:
    mig_dir = root / "services" / "api" / "migrations"
    if not mig_dir.is_dir():
        return []
    hits: list[str] = []
    for path in sorted(mig_dir.glob("*.sql")):
        body = path.read_text(encoding="utf-8", errors="replace")
        if "aisoc_cases" not in body or "acknowledged_at" not in body:
            continue
        if MIGRATION_ACK_WRITE.search(body):
            hits.append(path.relative_to(root).as_posix())
    return hits


def gate_escalation_ack_docs(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    readme = _read(root, README)
    bridge_doc = _bridge_module_doc(root)

    if not readme:
        findings.append(Finding(str(README), "missing; operators cannot read what stops paging"))
    if not bridge_doc:
        findings.append(Finding(str(BRIDGE), "module docstring missing"))

    for rel, text in ((README, readme), (BRIDGE, bridge_doc)):
        if not text:
            continue
        plain = _normalize_doc(text)
        for phrase in FORBIDDEN_DOC_PHRASES:
            if phrase in plain:
                findings.append(
                    Finding(
                        str(rel),
                        f"still claims {phrase!r}; only the war-room acknowledge decision writes the ack clock",
                    )
                )
        if not WAR_ROOM_ACK.search(plain):
            findings.append(
                Finding(
                    str(rel),
                    "does not name the war-room acknowledge decision as the ack-clock writer",
                )
            )
        if rel == README:
            if not EXCLUSIVE_README_WRITER.search(plain):
                findings.append(
                    Finding(
                        str(rel),
                        "must say today only the war-room acknowledge decision (exclusive writer)",
                    )
                )
        else:
            if not EXCLUSIVE_WRITER.search(plain):
                findings.append(
                    Finding(
                        str(rel),
                        "module docstring must say today only the war-room acknowledge decision writes it",
                    )
                )
        if ALT_ACK_WRITER.search(plain):
            findings.append(
                Finding(
                    str(rel),
                    "names an alternate ack-clock writer (console, join, or trailing or-clause)",
                )
            )
        if "war_room.py" not in text:
            findings.append(
                Finding(
                    str(rel),
                    "does not point at services/api/app/services/war_room.py as the writer",
                )
            )

    writers: list[str] = []
    for path in (root / "services").rglob("*.py"):
        py_rel = path.relative_to(root).as_posix()
        if "/migrations/" in py_rel or py_rel.startswith("services/api/migrations/"):
            continue
        body = path.read_text(encoding="utf-8", errors="replace")
        if _mentions_case_ack_write(body):
            writers.append(py_rel)

    expected = WAR_ROOM.as_posix()
    if writers != [expected]:
        findings.append(
            Finding(
                "runtime writers",
                f"expected only {expected}, found {sorted(writers) or 'none'}",
            )
        )

    if not (root / WAR_ROOM).is_file():
        findings.append(Finding(str(WAR_ROOM), "missing; cannot verify the ack-clock writer"))

    channel_block = _read(root, WAR_ROOM)
    findings.extend(_gate_war_room_ack_path(channel_block))

    mig_writers = _migration_case_ack_writers(root)
    if mig_writers:
        findings.append(
            Finding(
                "migrations",
                f"unexpected aisoc_cases.acknowledged_at writers in SQL: {mig_writers}",
            )
        )

    return findings


WAR_ROOM_ACK_SNIPPET = (
    'CHANNEL_DECISIONS = frozenset({"acknowledge", "escalate", "resolve", "note"})\n'
    'if decision == "acknowledge":\n'
    '    "UPDATE aisoc_cases SET acknowledged_at = COALESCE(acknowledged_at, :now)"\n'
    'elif decision == "escalate":\n'
    "    pass\n"
)

GOOD_README = """# escalations

- **What stops the clock:** only `aisoc_cases.acknowledged_at` being written —
  today only the war-room **acknowledge** decision in
  `services/api/app/services/war_room.py`.
"""

GOOD_BRIDGE_DOC = '''"""Ack bridge.

* **"Acknowledged" means `acknowledged_at` was written** — today only the
  war-room **acknowledge** decision writes it (`war_room.py` stamps it with
  COALESCE).
"""
'''


def _write_minimal_tree(dest: Path, *, readme: str, bridge_doc: str, war_room: str) -> None:
    (dest / README).parent.mkdir(parents=True, exist_ok=True)
    (dest / README).write_text(readme, encoding="utf-8")
    bridge = dest / BRIDGE
    bridge.parent.mkdir(parents=True, exist_ok=True)
    bridge.write_text(f"{bridge_doc}\nfrom __future__ import annotations\n", encoding="utf-8")
    war = dest / WAR_ROOM
    war.parent.mkdir(parents=True, exist_ok=True)
    war.write_text(war_room, encoding="utf-8")


def _self_test() -> int:
    print(f"{Path(__file__).name} {SELF_TEST_FLAG}\n")
    ok = True

    good = Path(tempfile.mkdtemp(prefix="esc-ack-good-"))
    try:
        _write_minimal_tree(
            good,
            readme=GOOD_README,
            bridge_doc=GOOD_BRIDGE_DOC,
            war_room=WAR_ROOM_ACK_SNIPPET,
        )
        passed = not gate_escalation_ack_docs(good)
        ok &= passed
        print(f"  {'PASS' if passed else 'FAIL'}  accurate docs pass")
    finally:
        shutil.rmtree(good, ignore_errors=True)

    bad = Path(tempfile.mkdtemp(prefix="esc-ack-bad-"))
    try:
        stale = GOOD_README.replace(
            "war-room **acknowledge**",
            "console's acknowledge action and joining the case's war room",
        )
        _write_minimal_tree(
            bad,
            readme=stale,
            bridge_doc=GOOD_BRIDGE_DOC,
            war_room=WAR_ROOM_ACK_SNIPPET,
        )
        caught = bool(gate_escalation_ack_docs(bad))
        ok &= caught
        print(f"  {'PASS' if caught else 'FAIL'}  stale console-ack claim is refused")
    finally:
        shutil.rmtree(bad, ignore_errors=True)

    extra = Path(tempfile.mkdtemp(prefix="esc-ack-extra-writer-"))
    try:
        _write_minimal_tree(
            extra,
            readme=GOOD_README + "\nThe web UI PATCH is also an ack-clock writer.\n",
            bridge_doc=GOOD_BRIDGE_DOC,
            war_room=WAR_ROOM_ACK_SNIPPET,
        )
        caught_extra = bool(gate_escalation_ack_docs(extra))
        ok &= caught_extra
        print(f"  {'PASS' if caught_extra else 'FAIL'}  extra ack-clock writer claim is refused")
    finally:
        shutil.rmtree(extra, ignore_errors=True)

    concat = Path(tempfile.mkdtemp(prefix="esc-ack-concat-"))
    try:
        _write_minimal_tree(
            concat,
            readme=GOOD_README,
            bridge_doc=GOOD_BRIDGE_DOC,
            war_room=WAR_ROOM_ACK_SNIPPET,
        )
        rogue = concat / "services/api/app/cases.py"
        rogue.parent.mkdir(parents=True, exist_ok=True)
        rogue.write_text('cur.execute("UPDATE " + "aisoc_cases SET acknowledged_at = now()")\n', encoding="utf-8")
        caught_concat = bool(gate_escalation_ack_docs(concat))
        ok &= caught_concat
        print(f"  {'PASS' if caught_concat else 'FAIL'}  split-string SQL writer is refused")
    finally:
        shutil.rmtree(concat, ignore_errors=True)

    paraphrase = Path(tempfile.mkdtemp(prefix="esc-ack-paraphrase-"))
    try:
        readme_bad = GOOD_README.replace(
            "`services/api/app/services/war_room.py`.",
            "`services/api/app/services/war_room.py`, or clicking Acknowledge on the case in the console.",
        )
        _write_minimal_tree(
            paraphrase,
            readme=readme_bad,
            bridge_doc=GOOD_BRIDGE_DOC,
            war_room=WAR_ROOM_ACK_SNIPPET,
        )
        caught_para = bool(gate_escalation_ack_docs(paraphrase))
        ok &= caught_para
        print(f"  {'PASS' if caught_para else 'FAIL'}  console paraphrase in README is refused")
    finally:
        shutil.rmtree(paraphrase, ignore_errors=True)

    drop_only = Path(tempfile.mkdtemp(prefix="esc-ack-drop-only-"))
    try:
        _write_minimal_tree(
            drop_only,
            readme=GOOD_README,
            bridge_doc=GOOD_BRIDGE_DOC.replace("today only the", "today the"),
            war_room=WAR_ROOM_ACK_SNIPPET,
        )
        caught_drop = bool(gate_escalation_ack_docs(drop_only))
        ok &= caught_drop
        print(f"  {'PASS' if caught_drop else 'FAIL'}  bridge doc without only is refused")
    finally:
        shutil.rmtree(drop_only, ignore_errors=True)

    wrong_branch = Path(tempfile.mkdtemp(prefix="esc-ack-wrong-branch-"))
    try:
        war = (
            'CHANNEL_DECISIONS = frozenset({"acknowledge", "escalate"})\n'
            'if decision == "acknowledge":\n    pass\n'
            'elif decision == "escalate":\n'
            '    "UPDATE aisoc_cases SET acknowledged_at = COALESCE(acknowledged_at, :now)"\n'
        )
        _write_minimal_tree(
            wrong_branch,
            readme=GOOD_README,
            bridge_doc=GOOD_BRIDGE_DOC,
            war_room=war,
        )
        caught_branch = bool(gate_escalation_ack_docs(wrong_branch))
        ok &= caught_branch
        print(f"  {'PASS' if caught_branch else 'FAIL'}  ack write outside acknowledge branch is refused")
    finally:
        shutil.rmtree(wrong_branch, ignore_errors=True)

    triple = Path(tempfile.mkdtemp(prefix="esc-ack-triple-quote-"))
    try:
        _write_minimal_tree(
            triple,
            readme=GOOD_README,
            bridge_doc=(
                "'''Ack bridge.\n\n"
                "* today only the war-room acknowledge decision writes it "
                "(`services/api/app/services/war_room.py`).\n'''\n"
            ),
            war_room=WAR_ROOM_ACK_SNIPPET,
        )
        caught_triple = gate_escalation_ack_docs(triple)
        passed_triple = len(caught_triple) == 0
        ok &= passed_triple
        print(f"  {'PASS' if passed_triple else 'FAIL'}  triple-quoted bridge docstring is read without crashing")
    finally:
        shutil.rmtree(triple, ignore_errors=True)

    noise = Path(tempfile.mkdtemp(prefix="esc-ack-noise-"))
    try:
        _write_minimal_tree(
            noise,
            readme=GOOD_README,
            bridge_doc=GOOD_BRIDGE_DOC,
            war_room=WAR_ROOM_ACK_SNIPPET,
        )
        rogue = noise / "services/api/app/noise.py"
        rogue.parent.mkdir(parents=True, exist_ok=True)
        rogue.write_text(
            'def f(row):\n    db.execute("UPDATE aisoc_cases SET status = %s", row["status"])\n    return row["acknowledged_at"]\n',
            encoding="utf-8",
        )
        passed_noise = len(gate_escalation_ack_docs(noise)) == 0
        ok &= passed_noise
        print(f"  {'PASS' if passed_noise else 'FAIL'}  status-only UPDATE is not a false-positive writer")
    finally:
        shutil.rmtree(noise, ignore_errors=True)

    empty = Path(tempfile.mkdtemp(prefix="esc-ack-empty-"))
    try:
        refused = bool(gate_escalation_ack_docs(empty))
        ok &= refused
        print(f"  {'PASS' if refused else 'FAIL'}  empty tree is not reported clean")
    finally:
        shutil.rmtree(empty, ignore_errors=True)

    print()
    if not ok:
        print(f"{Path(__file__).name}: self-test FAILED")
        return 1
    print(f"{Path(__file__).name}: self-test OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(SELF_TEST_FLAG, action="store_true")
    args = parser.parse_args()
    if args.self_test:
        return _self_test()

    root = repo_root()
    if not (root / "services" / "escalations").is_dir():
        print(f"{Path(__file__).name}: escalations service absent — nothing to check.", file=sys.stderr)
        return 2

    findings = gate_escalation_ack_docs(root)
    if findings:
        print("Escalation ack-clock documentation disagrees with the code:\n", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding.render()}", file=sys.stderr)
        return 1

    print("OK - escalation docs name the war-room acknowledge decision as the only case ack-clock writer.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
