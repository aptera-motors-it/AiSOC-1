"""CI entry for ``scripts/check_service_container_user.py``."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
GATE = REPO / "scripts" / "check_service_container_user.py"


def _load_gate():
    name = "check_service_container_user"
    spec = importlib.util.spec_from_file_location(name, GATE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def test_service_dockerfiles_declare_non_root_user() -> None:
    gate = _load_gate()
    findings = gate.scan(REPO)
    assert not findings, "\n".join(f"{rel}: {info.stage}" for rel, info in findings)


def test_service_container_user_gate_self_test() -> None:
    out = subprocess.run(  # noqa: S603
        [sys.executable, str(GATE), "--self-test"],
        capture_output=True,
        text=True,
        cwd=REPO,
        check=False,
    )
    assert out.returncode == 0, out.stdout + out.stderr
