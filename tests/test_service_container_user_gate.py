"""F69: first-party service containers must not run as root.

The behavioural half is ``scripts/check_service_container_user.py``, which
reads every ``services/*/Dockerfile`` and requires a non-root ``USER`` in the
runtime stage. This module invokes that gate the way CI would.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
GATE = REPO / "scripts" / "check_service_container_user.py"


def _load_gate():
    spec = importlib.util.spec_from_file_location("check_service_container_user", GATE)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_service_dockerfiles_declare_non_root_user() -> None:
    """No service image may run as uid 0 by default."""
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
