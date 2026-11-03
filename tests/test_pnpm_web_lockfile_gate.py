"""The root pnpm lockfile gate must catch minimatch and deepmerge drift.

``pnpm audit`` on the root workspace still reddened every push with moderate
``minimatch`` and low ``deepmerge`` advisories while ``security_audit.py`` only
failed on high/critical findings. The gate below reads resolved versions in
``pnpm-lock.yaml`` and fails closed on the known-vulnerable ranges.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
GATE = REPO_ROOT / "scripts" / "check_pnpm_web_lockfile.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_pnpm_web_lockfile", GATE)
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_pnpm_web_lockfile"] = module
    spec.loader.exec_module(module)
    return module


gate = _load()


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    lock = "\n".join(
        [
            "lockfileVersion: '9.0'",
            "packages:",
            "  /minimatch@11.0.4:",
            "    resolution: {integrity: sha512-ok}",
            "  /deepmerge@4.1.2:",
            "    resolution: {integrity: sha512-ok}",
        ]
    )
    (tmp_path / "pnpm-lock.yaml").write_text(lock, encoding="utf-8")
    return tmp_path


def test_this_repository_passes() -> None:
    problems = gate.check_root_lockfile(REPO_ROOT)
    assert problems == [], problems


def test_clean_fixture_passes(tree: Path) -> None:
    assert gate.check_root_lockfile(tree) == []


def test_flags_scoped_vulnerable_minimatch(tree: Path) -> None:
    text = (tree / "pnpm-lock.yaml").read_text(encoding="utf-8").replace("11.0.4", "10.2.6")
    (tree / "pnpm-lock.yaml").write_text(text, encoding="utf-8")
    problems = gate.check_root_lockfile(tree)
    assert any("minimatch@10.2.6" in p for p in problems), problems


def test_allows_legacy_minimatch_three(tree: Path) -> None:
    text = (tree / "pnpm-lock.yaml").read_text(encoding="utf-8").replace(
        "/minimatch@11.0.4:", "  /minimatch@3.1.5:\n    resolution: {integrity: sha512-legacy}\n  /minimatch@11.0.4:"
    )
    (tree / "pnpm-lock.yaml").write_text(text, encoding="utf-8")
    assert gate.check_root_lockfile(tree) == []


def test_flags_vulnerable_deepmerge(tree: Path) -> None:
    text = (tree / "pnpm-lock.yaml").read_text(encoding="utf-8").replace("4.1.2", "4.3.1")
    (tree / "pnpm-lock.yaml").write_text(text, encoding="utf-8")
    problems = gate.check_root_lockfile(tree)
    assert any("deepmerge@4.3.1" in p for p in problems), problems


def test_missing_lockfile_is_not_clean(tree: Path) -> None:
    (tree / "pnpm-lock.yaml").unlink()
    problems = gate.check_root_lockfile(tree)
    assert problems and "missing" in problems[0]


def test_flags_quoted_minimatch_key(tree: Path) -> None:
    text = (tree / "pnpm-lock.yaml").read_text(encoding="utf-8").replace(
        "/minimatch@11.0.4:", "'/minimatch@10.2.6':"
    )
    (tree / "pnpm-lock.yaml").write_text(text, encoding="utf-8")
    problems = gate.check_root_lockfile(tree)
    assert any("minimatch@10.2.6" in p for p in problems), problems


def test_gate_cli_on_this_repository() -> None:
    assert gate.main(["--root", str(REPO_ROOT)]) == 0
